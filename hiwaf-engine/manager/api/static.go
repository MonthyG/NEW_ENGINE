package api

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxZip        = 100 << 20 // upload size
	maxUnzipped   = 500 << 20 // total extracted size
	maxZipEntries = 20000
)

// uploadStatic replaces a static site's files with the contents of a zip
// archive (multipart field "file"). The archive is extracted next to the
// site directory and swapped in, so the site never serves a half-written
// tree.
func (a *API) uploadStatic(w http.ResponseWriter, r *http.Request) {
	if a.opt.StaticDir == "" {
		a.writeErr(w, &httpError{status: http.StatusConflict, msg: "static sites are not configured (static_dir)"})
		return
	}
	id := r.PathValue("id")
	var isStatic bool
	recs, err := a.st.ListSites(r.Context())
	if err != nil {
		a.writeErr(w, err)
		return
	}
	found := false
	for _, rec := range recs {
		if rec.ID == id {
			found, isStatic = true, rec.Doc.Type == "static"
		}
	}
	if !found {
		a.writeErr(w, errNotFound)
		return
	}
	if !isStatic {
		a.writeErr(w, badRequest("type", "the site is not a static site"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxZip+1<<20)
	f, _, err := r.FormFile("file")
	if err != nil {
		a.writeErr(w, badRequest("file", "a zip file is required: "+err.Error()))
		return
	}
	defer f.Close()
	tmp, err := os.CreateTemp(a.opt.StaticDir, ".upload-*.zip")
	if err != nil {
		a.writeErr(w, err)
		return
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	size, err := io.Copy(tmp, f)
	if err != nil {
		a.writeErr(w, badRequest("file", "upload failed: "+err.Error()))
		return
	}
	zr, err := zip.NewReader(tmp, size)
	if err != nil {
		a.writeErr(w, badRequest("file", "not a zip archive"))
		return
	}
	stage, err := os.MkdirTemp(a.opt.StaticDir, ".stage-"+id+"-")
	if err != nil {
		a.writeErr(w, err)
		return
	}
	defer os.RemoveAll(stage)
	n, err := extract(zr, stage)
	if err != nil {
		a.writeErr(w, badRequest("file", err.Error()))
		return
	}
	dst := filepath.Join(a.opt.StaticDir, id)
	old := dst + ".old"
	_ = os.RemoveAll(old)
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, old); err != nil {
			a.writeErr(w, err)
			return
		}
	}
	if err := os.Rename(stage, dst); err != nil {
		_ = os.Rename(old, dst)
		a.writeErr(w, err)
		return
	}
	_ = os.Chmod(dst, 0o755)
	_ = os.RemoveAll(old)
	writeJSON(w, http.StatusOK, map[string]int{"files": n})
}

// extract writes the archive's regular files under dir. Paths that escape
// dir, links and oversized archives are refused. A single top-level folder
// holding everything (as made by zipping a folder) is stripped.
func extract(zr *zip.Reader, dir string) (int, error) {
	if len(zr.File) > maxZipEntries {
		return 0, fmt.Errorf("too many entries (max %d)", maxZipEntries)
	}
	prefix := commonDir(zr.File)
	var total int64
	n := 0
	for _, zf := range zr.File {
		name := strings.TrimPrefix(strings.ReplaceAll(zf.Name, `\`, "/"), prefix)
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		if !zf.Mode().IsRegular() {
			return 0, fmt.Errorf("%s: only regular files are allowed", zf.Name)
		}
		clean := filepath.Clean(filepath.FromSlash(name))
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return 0, fmt.Errorf("%s: path escapes the site directory", zf.Name)
		}
		target := filepath.Join(dir, clean)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return 0, err
		}
		rc, err := zf.Open()
		if err != nil {
			return 0, err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return 0, err
		}
		written, err := io.Copy(out, io.LimitReader(rc, maxUnzipped-total+1))
		rc.Close()
		cerr := out.Close()
		if err != nil {
			return 0, err
		}
		if cerr != nil {
			return 0, cerr
		}
		total += written
		if total > maxUnzipped {
			return 0, errors.New("archive is too large when extracted")
		}
		n++
	}
	if n == 0 {
		return 0, errors.New("the archive has no files")
	}
	return n, nil
}

// commonDir returns "dir/" when every entry lives under the same top folder.
func commonDir(files []*zip.File) string {
	prefix := ""
	for i, f := range files {
		name := strings.ReplaceAll(f.Name, `\`, "/")
		top, _, ok := strings.Cut(name, "/")
		if !ok {
			return ""
		}
		if i == 0 {
			prefix = top + "/"
		} else if top+"/" != prefix {
			return ""
		}
	}
	return prefix
}
