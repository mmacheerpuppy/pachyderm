package s3

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gogo/protobuf/types"
	"github.com/gorilla/mux"
	"github.com/pachyderm/pachyderm/src/client"
	pfsClient "github.com/pachyderm/pachyderm/src/client/pfs"
	"github.com/pachyderm/pachyderm/src/server/pkg/errutil"
	"github.com/pachyderm/pachyderm/src/server/pkg/uuid"
	"github.com/pachyderm/s2"
)

var multipartChunkPathMatcher = regexp.MustCompile(`([^/]+)/([^/]+)/(.+)/([^/]+)/(\d+)`)
var multipartKeepPathMatcher = regexp.MustCompile(`([^/]+)/([^/]+)/(.+)/([^/]+)/\.keep`)

func multipartChunkArgs(path string) (repo string, branch string, key string, uploadID string, partNumber int, err error) {
	match := multipartChunkPathMatcher.FindStringSubmatch(path)

	if len(match) == 0 {
		err = errors.New("invalid file path found in multipath bucket")
		return
	}

	repo = match[1]
	branch = match[2]
	key = match[3]
	uploadID = match[4]
	partNumber, err = strconv.Atoi(match[5])
	if err != nil {
		err = fmt.Errorf("invalid file path found in multipath bucket: %s", err)
		return
	}
	return
}

func multipartKeepArgs(path string) (repo string, branch string, key string, uploadID string, err error) {
	match := multipartKeepPathMatcher.FindStringSubmatch(path)

	if len(match) == 0 {
		err = errors.New("invalid file path found in multipath bucket")
		return
	}

	repo = match[1]
	branch = match[2]
	key = match[3]
	uploadID = match[4]
	return
}

func parentDirPath(repo, branch, key, uploadID string) string {
	return fmt.Sprintf("%s/%s/%s/%s", repo, branch, key, uploadID)
}

func chunkPath(repo, branch, key, uploadID string, partNumber int) string {
	return fmt.Sprintf("%s/%d", parentDirPath(repo, branch, key, uploadID), partNumber)
}

func keepPath(repo, branch, key, uploadID string) string {
	return fmt.Sprintf("%s/.keep", parentDirPath(repo, branch, key, uploadID))
}

func (c *controller) ensureRepo(pc *client.APIClient) error {
	_, err := pc.InspectBranch(c.repo, "master")
	if err != nil {
		err = pc.CreateRepo(c.repo)
		if err != nil && !strings.Contains(err.Error(), "as it already exists") {
			return err
		}

		err = pc.CreateBranch(c.repo, "master", "", nil)
		if err != nil && !strings.Contains(err.Error(), "as it already exists") {
			return err
		}
	}

	return nil
}

func (c *controller) ListMultipart(r *http.Request, bucket, keyMarker, uploadIDMarker string, maxUploads int) (isTruncated bool, uploads []s2.Upload, err error) {
	vars := mux.Vars(r)
	pc, err := c.pachClient(vars["authAccessKey"])
	if err != nil {
		return
	}
	repo, branch, err := bucketArgs(r, bucket)
	if err != nil {
		return
	}
	_, err = pc.InspectBranch(repo, branch)
	if err != nil {
		err = maybeNotFoundError(r, err)
		return
	}
	if err = c.ensureRepo(pc); err != nil {
		return
	}

	err = pc.GlobFileF(c.repo, "master", fmt.Sprintf("%s/%s/*/*/.keep", repo, branch), func(fileInfo *pfsClient.FileInfo) error {
		_, _, key, uploadID, err := multipartKeepArgs(fileInfo.File.Path)
		if err != nil {
			return nil
		}

		if key <= keyMarker || uploadID <= uploadIDMarker {
			return nil
		}

		if len(uploads) >= maxUploads {
			if maxUploads > 0 {
				isTruncated = true
			}
			return errutil.ErrBreak
		}

		timestamp, err := types.TimestampFromProto(fileInfo.Committed)
		if err != nil {
			return err
		}

		uploads = append(uploads, s2.Upload{
			Key:          key,
			UploadID:     uploadID,
			Initiator:    defaultUser,
			StorageClass: globalStorageClass,
			Initiated:    timestamp,
		})

		return nil
	})

	return
}

func (c *controller) InitMultipart(r *http.Request, bucket, key string) (uploadID string, err error) {
	vars := mux.Vars(r)
	pc, err := c.pachClient(vars["authAccessKey"])
	if err != nil {
		return
	}
	repo, branch, err := bucketArgs(r, bucket)
	if err != nil {
		return
	}
	_, err = pc.InspectBranch(repo, branch)
	if err != nil {
		err = maybeNotFoundError(r, err)
		return
	}
	if err = c.ensureRepo(pc); err != nil {
		return "", err
	}

	uploadID = uuid.NewWithoutDashes()

	path := fmt.Sprintf("%s/.keep", parentDirPath(repo, branch, key, uploadID))
	_, err = pc.PutFileOverwrite(c.repo, "master", path, strings.NewReader(""), 0)
	if err != nil {
		return
	}
	return
}

func (c *controller) AbortMultipart(r *http.Request, bucket, key, uploadID string) error {
	vars := mux.Vars(r)
	pc, err := c.pachClient(vars["authAccessKey"])
	if err != nil {
		return err
	}
	repo, branch, err := bucketArgs(r, bucket)
	if err != nil {
		return err
	}
	_, err = pc.InspectBranch(repo, branch)
	if err != nil {
		return maybeNotFoundError(r, err)
	}
	if err = c.ensureRepo(pc); err != nil {
		return err
	}

	_, err = pc.InspectFile(c.repo, "master", keepPath(repo, branch, key, uploadID))
	if err != nil {
		return s2.NoSuchUploadError(r)
	}

	err = pc.DeleteFile(c.repo, "master", parentDirPath(repo, branch, key, uploadID))
	if err != nil {
		return s2.InternalError(r, err)
	}

	return nil
}

func (c *controller) CompleteMultipart(r *http.Request, bucket, key, uploadID string, parts []s2.Part) (location, etag, version string, err error) {
	vars := mux.Vars(r)
	pc, err := c.pachClient(vars["authAccessKey"])
	if err != nil {
		return
	}
	repo, branch, err := bucketArgs(r, bucket)
	if err != nil {
		return
	}
	_, err = pc.InspectBranch(repo, branch)
	if err != nil {
		err = maybeNotFoundError(r, err)
		return
	}
	if err = c.ensureRepo(pc); err != nil {
		return
	}

	_, err = pc.InspectFile(c.repo, "master", keepPath(repo, branch, key, uploadID))
	if err != nil {
		err = s2.NoSuchUploadError(r)
		return
	}

	for i, part := range parts {
		srcPath := chunkPath(repo, branch, key, uploadID, part.PartNumber)

		var fileInfo *pfsClient.FileInfo
		fileInfo, err = pc.InspectFile(c.repo, "master", srcPath)
		if err != nil {
			err = s2.InvalidPartError(r)
			return
		}

		// Only verify the ETag when it's of the same length as PFS file
		// hashes. This is because s3 clients will generally use md5 for
		// ETags, and would otherwise fail.
		expectedETag := fmt.Sprintf("%x", fileInfo.Hash)
		if len(part.ETag) == len(expectedETag) && part.ETag != expectedETag {
			err = s2.InvalidPartError(r)
			return
		}

		if i < len(parts)-1 && fileInfo.SizeBytes < 5*1024*1024 {
			// each part, except for the last, is expected to be at least 5mb
			// in s3
			err = s2.EntityTooSmallError(r)
			return
		}

		err = pc.CopyFile(c.repo, "master", srcPath, repo, branch, key, false)
		if err != nil {
			err = s2.InternalError(r, err)
			return
		}
	}

	// TODO: verify that this works
	err = pc.DeleteFile(c.repo, "master", parentDirPath(repo, branch, key, uploadID))
	if err != nil {
		return
	}

	fileInfo, err := pc.InspectFile(repo, branch, key)
	if err != nil {
		return
	}

	location = globalLocation
	etag = fmt.Sprintf("%x", fileInfo.Hash)
	version = fileInfo.File.Commit.ID
	return
}

func (c *controller) ListMultipartChunks(r *http.Request, bucket, key, uploadID string, partNumberMarker, maxParts int) (initiator, owner *s2.User, storageClass string, isTruncated bool, parts []s2.Part, err error) {
	vars := mux.Vars(r)
	pc, err := c.pachClient(vars["authAccessKey"])
	if err != nil {
		return
	}
	repo, branch, err := bucketArgs(r, bucket)
	if err != nil {
		return
	}
	_, err = pc.InspectBranch(repo, branch)
	if err != nil {
		err = maybeNotFoundError(r, err)
		return
	}
	if err = c.ensureRepo(pc); err != nil {
		return
	}

	err = pc.GlobFileF(c.repo, "master", fmt.Sprintf("%s/%s/%s/%s/*", repo, branch, key, uploadID), func(fileInfo *pfsClient.FileInfo) error {
		_, _, _, _, partNumber, err := multipartChunkArgs(fileInfo.File.Path)
		if err != nil {
			return nil
		}

		if partNumber <= partNumberMarker {
			return nil
		}

		if len(parts) >= maxParts {
			if maxParts > 0 {
				isTruncated = true
			}
			return errutil.ErrBreak
		}

		parts = append(parts, s2.Part{
			PartNumber: partNumber,
			ETag:       fmt.Sprintf("%x", fileInfo.Hash),
		})

		return nil
	})
	if err != nil {
		return
	}

	initiator = &defaultUser
	owner = &defaultUser
	storageClass = globalStorageClass
	return
}

func (c *controller) UploadMultipartChunk(r *http.Request, bucket, key, uploadID string, partNumber int, reader io.Reader) (etag string, err error) {
	vars := mux.Vars(r)
	pc, err := c.pachClient(vars["authAccessKey"])
	if err != nil {
		return
	}
	repo, branch, err := bucketArgs(r, bucket)
	if err != nil {
		return
	}
	_, err = pc.InspectBranch(repo, branch)
	if err != nil {
		err = maybeNotFoundError(r, err)
		return
	}
	if err = c.ensureRepo(pc); err != nil {
		return "", err
	}

	_, err = pc.InspectFile(c.repo, "master", keepPath(repo, branch, key, uploadID))
	if err != nil {
		err = s2.NoSuchUploadError(r)
		return
	}

	path := chunkPath(repo, branch, key, uploadID, partNumber)
	_, err = pc.PutFileOverwrite(c.repo, "master", path, reader, 0)
	if err != nil {
		return
	}

	fileInfo, err := pc.InspectFile(c.repo, "master", path)
	if err != nil {
		return
	}

	etag = fmt.Sprintf("%x", fileInfo.Hash)
	return
}

func (c *controller) DeleteMultipartChunk(r *http.Request, bucket, key, uploadID string, partNumber int) error {
	vars := mux.Vars(r)
	pc, err := c.pachClient(vars["authAccessKey"])
	if err != nil {
		return err
	}
	repo, branch, err := bucketArgs(r, bucket)
	if err != nil {
		return err
	}
	_, err = pc.InspectBranch(repo, branch)
	if err != nil {
		return maybeNotFoundError(r, err)
	}
	if err = c.ensureRepo(pc); err != nil {
		return err
	}

	_, err = pc.InspectFile(c.repo, "master", keepPath(repo, branch, key, uploadID))
	if err != nil {
		return s2.NoSuchUploadError(r)
	}

	path := chunkPath(repo, branch, key, uploadID, partNumber)
	return pc.DeleteFile(c.repo, "master", path)
}
