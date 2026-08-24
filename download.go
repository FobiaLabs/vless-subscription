package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const ghAPI = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"

// downloadLatest скачивает sing-box последнего релиза под текущие GOOS/GOARCH.
func downloadLatest(outPath string) error {
	resp, err := http.Get(ghAPI)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github api: HTTP %d", resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return err
	}

	want := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	isWin := runtime.GOOS == "windows"
	for _, a := range rel.Assets {
		name := strings.ToLower(a.Name)
		if !strings.Contains(name, want) || strings.Contains(name, "android") {
			continue
		}
		switch {
		case isWin && strings.HasSuffix(name, ".zip"):
			return fetchZip(a.URL, outPath)
		case !isWin && strings.HasSuffix(name, ".tar.gz"):
			return fetchTarGz(a.URL, outPath)
		}
	}
	return fmt.Errorf("не найден релиз для %s", want)
}

func fetchTarGz(url, outName string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) == "sing-box" {
			f, err := os.OpenFile(outName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			f.Close()
			return err
		}
	}
	return fmt.Errorf("sing-box не найден в архиве")
}

func fetchZip(url, outName string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		if base == "sing-box.exe" || base == "sing-box" {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			out, err := os.OpenFile(outName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				rc.Close()
				return err
			}
			_, err = io.Copy(out, rc)
			out.Close()
			rc.Close()
			return err
		}
	}
	return fmt.Errorf("sing-box.exe не найден в архиве")
}
