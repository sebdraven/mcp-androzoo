package androzoo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// IndexPath is the nightly catalogue of every APK AndroZoo holds. It is served
// as a static file rather than through the API, and is public: the key is sent
// when there is one, but the download works without.
const IndexPath = "/static/lists/latest.csv.gz"

// IndexInfo describes what the server agreed to send.
type IndexInfo struct {
	// TotalSize is the size of the whole catalogue when the server reports it,
	// 0 otherwise. On a resumed transfer it is the total, not what is left.
	TotalSize int64
	// Resumed reports whether the server honoured the requested offset. When
	// false after asking for one, the caller must start the file over.
	Resumed bool
	// LastModified is the server's date for the file, which is the only thing
	// that tells two nightly builds apart.
	LastModified string
}

// IndexReader opens the catalogue for reading, from offset if the server
// supports it. The caller closes the reader.
func (c *Client) IndexReader(ctx context.Context, offset int64) (io.ReadCloser, IndexInfo, error) {
	u := c.baseURL + IndexPath
	if c.key != "" {
		u += "?apikey=" + c.key
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, IndexInfo{}, err
	}
	if offset > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, IndexInfo{}, fmt.Errorf("androzoo catalogue: %w", err)
	}

	info := IndexInfo{LastModified: resp.Header.Get("Last-Modified")}
	switch resp.StatusCode {
	case http.StatusOK:
		info.TotalSize = resp.ContentLength
	case http.StatusPartialContent:
		info.Resumed = true
		info.TotalSize = totalFromContentRange(resp.Header.Get("Content-Range"))
		if info.TotalSize == 0 && resp.ContentLength > 0 {
			info.TotalSize = offset + resp.ContentLength
		}
	case http.StatusRequestedRangeNotSatisfiable:
		resp.Body.Close()
		return nil, IndexInfo{}, fmt.Errorf("androzoo catalogue: the server refused to resume at byte %d — the file it holds has changed, start the download over", offset)
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, IndexInfo{}, &APIError{StatusCode: resp.StatusCode, Endpoint: "catalogue", Body: string(body)}
	}
	return resp.Body, info, nil
}

// totalFromContentRange reads the total out of "bytes 100-999/1000".
func totalFromContentRange(v string) int64 {
	i := strings.LastIndex(v, "/")
	if i < 0 {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v[i+1:]), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
