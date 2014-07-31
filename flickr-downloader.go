package main

import "bytes"
import "crypto/hmac"
import "crypto/sha1"
import "encoding/base64"
import "encoding/json"
import "flag"
import "fmt"
import "io/ioutil"
import "math/rand"
import "net/http"
import "net/url"
import "os"
import "sort"
import "strconv"
import "strings"
import "time"

const METHOD_GET = "GET"
const SIZES_DOWNLOADERS = 30
const PHOTO_DOWNLOADERS = 10

// convert an parameter encoded string to a map
func params_to_map(param_str string) map[string]string {
	parts := strings.Split(param_str, "&")
	params := map[string]string{}
	for i, part := range parts {
		key_val := strings.Split(part, "=")
		key := ""
		value := ""
		if len(key_val) == 1 {
			key = strconv.Itoa(i)
			value = key_val[0]
		} else {
			key = key_val[0]
			value = key_val[1]
		}
		params[key] = value
	}
	return params
}

func sort_params(params string) string {
	parts := strings.Split(params, "&")
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

func escape(v string) string {
	return url.QueryEscape(v)
}

func parameter_string(params map[string]string) string {
	keys := make([]string, 0)
	escaped_params := make(map[string]string)
	for key, value := range params {
		key = escape(key)
		keys = append(keys, key)
		escaped_params[key] = escape(value)
	}

	sort.Strings(keys)

	// buffer to generate the output
	var buffer bytes.Buffer

	// write the values
	for i, key := range keys {
		if i > 0 {
			buffer.WriteString("&")
		}
		buffer.WriteString(key)
		buffer.WriteString("=")
		buffer.WriteString(escaped_params[key])
	}

	return buffer.String()
}

func calculate_signature(http_method, url, consumer_secret, token_secret string, params map[string]string) string {

	// calculate signature
	byte_key := []byte(consumer_secret + "&" + token_secret)
	hasher := hmac.New(sha1.New, byte_key)

	// write the method in uppercase
	hasher.Write([]byte(strings.ToUpper(http_method)))
	hasher.Write([]byte("&"))

	// write the url
	hasher.Write([]byte(escape(url)))
	hasher.Write([]byte("&"))

	// write the parameter string
	param_str := parameter_string(params)
	hasher.Write([]byte(escape(param_str)))

	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))

}

func random_nonce() string {
	return strconv.Itoa(rand.Int())
}

func timestamp() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func add_oauth_params(consumer_key string, where map[string]string) map[string]string {
	where["oauth_nonce"] = random_nonce()
	where["oauth_timestamp"] = timestamp()
	where["oauth_consumer_key"] = consumer_key
	where["oauth_signature_method"] = "HMAC-SHA1"
	where["oauth_version"] = "1.0"
	return where
}

func params_to_string(params map[string]string) string {
	var buffer bytes.Buffer

	after_first := false
	// write the values
	for key, value := range params {
		if after_first {
			buffer.WriteString("&")
		}
		buffer.WriteString(key)
		buffer.WriteString("=")
		buffer.WriteString(value)
		after_first = true
	}

	return buffer.String()

}

func request_token(key, secret string) map[string]string {
	params := add_oauth_params(key, map[string]string{
		"oauth_callback": "http://localhost/",
	})
	base_url := "https://www.flickr.com/services/oauth/request_token"
	oauth := OAuth{
		AppKey:    key,
		AppSecret: secret,
	}
	body := generic_call(base_url, oauth, params)
	return params_to_map(body)
}

func generic_call(base_url string, oauth OAuth, params map[string]string) string {

	effective_params := map[string]string{}
	add_to_map(effective_params, params)
	add_oauth_params(oauth.AppKey, effective_params)

	signature := calculate_signature(METHOD_GET, base_url, oauth.AppSecret, oauth.TokenSecret, effective_params)
	effective_params["oauth_signature"] = signature

	url := base_url + "?" + params_to_string(effective_params)

	req, _ := http.NewRequest(METHOD_GET, url, nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("ERROR", err)
		panic(err)
	}
	defer resp.Body.Close()

	body_bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("ERROR", err)
		panic(err)
	}

	return string(body_bytes)
}

func ask_permissions(key, secret string) {

	resp := request_token(key, secret)
	oauth_token := resp["oauth_token"]
	oauth_token_secret := resp["oauth_token_secret"]

	fmt.Println("Please, open this URL in your browser:")
	fmt.Println("https://www.flickr.com/services/oauth/authorize?oauth_token=" + oauth_token)
	fmt.Println()
	fmt.Println("The token secret is:", oauth_token_secret)
}

func access_token(options Options) map[string]string {

	params := add_oauth_params(options.AppKey, map[string]string{
		"oauth_token":    options.Token,
		"oauth_verifier": options.Verifier,
	})

	base_url := "https://www.flickr.com/services/oauth/access_token"

	body := generic_call(base_url, options.OAuth, params)

	return params_to_map(body)

}

type OAuth struct {
	// Application key and secret, provided by flickr
	AppKey, AppSecret string

	// Used by oauth for each
	Token, TokenSecret string
}

type Options struct {
	OAuth

	// Used when generating access token
	Verifier string

	// This value
	UserId string
}

func add_to_map(dst, src map[string]string) {
	for k, v := range src {
		dst[k] = v
	}
}

func call_method(oauth OAuth, method string, params map[string]string) string {

	effective_params := map[string]string{}
	add_to_map(effective_params, params)
	add_to_map(effective_params, map[string]string{
		"format":         "json",
		"nojsoncallback": "1",
		"method":         method,
		"oauth_token":    oauth.Token,
	})
	add_oauth_params(oauth.AppKey, effective_params)

	base_url := "https://api.flickr.com/services/rest"

	body := generic_call(base_url, oauth, effective_params)

	return body

}

// return the home directory
func get_home() string {
	var home string
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "HOME=") {
			continue
		}
		home = env[5:]
	}
	return home
}

// exists returns whether the given file or directory exists or not
func exists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func get_options_path() string {
	return get_home() + "/.flick-downloader"
}

func read_options() Options {
	options_path := get_options_path()
	if !exists(options_path) {
		// TODO: write instructions
		fmt.Println("options_path: " + options_path + " doesn't exist.")
		fmt.Println("Use:")
		fmt.Println("  ")
		flag.Parse()
		flag.Usage()
		os.Exit(0)
	}

	data, _ := ioutil.ReadFile(options_path)

	options := Options{}
	json.Unmarshal(data, &options)
	return options
}

func string_to_json(s string) map[string]interface{} {
	decoder := json.NewDecoder(strings.NewReader(s))
	obj := map[string]interface{}{}
	decoder.Decode(&obj)
	return obj
}

func get_photos_sizes_metadata_path() string {
	return get_home() + "/Flickr/metadata/sizes"
}

func get_photos_metadata_path() string {
	return get_home() + "/Flickr/metadata/photos"
}

func get_media_path() string {
	return get_home() + "/Flickr/photos"
}

func get_photos_path(page int) string {
	return get_photos_metadata_path() + "/photos-page-" + fmt.Sprintf("%03d", page) + ".json"
}

func get_photo_sizes_path(photo_id string) string {
	return get_photos_sizes_metadata_path() + "/" + photo_id + "-photo-sizes.json"
}

func get_photo_info_path(photo_id string) string {
	return get_photos_sizes_metadata_path() + "/" + photo_id + "-photo-info.json"
}

func get_media_location(photo_id string) string {
	dir := get_media_path() + "/" + photo_id[0:4]
	os.Mkdir(dir, 0755)
	return dir + "/" + photo_id + ".jpg"
}

func save_photos_metadata(page int, str string) {
	ioutil.WriteFile(get_photos_path(page), []byte(str), 0644)
}

func get_all_photos(options Options) {

	fmt.Println("Downloading photos page 1")

	params := map[string]string{"user_id": options.UserId}
	page1_str := call_method(options.OAuth, "flickr.people.getPhotos", params)
	page1_obj := string_to_json(page1_str)

	photos, _ := page1_obj["photos"].(map[string]interface{})
	// fmt.Println("photos:", photos)
	total_pages := int(photos["pages"].(float64))

	save_photos_metadata(1, page1_str)

	for i := 2; i <= total_pages; i++ {
		if exists(get_photos_path(i)) {
			fmt.Println("Skipping page", i, "because it already exists")
			continue
		}
		fmt.Println("Downloading photos page", i, "of", total_pages)
		params["page"] = strconv.Itoa(i)
		page_str := call_method(options.OAuth, "flickr.people.getPhotos", params)

		save_photos_metadata(i, page_str)
	}

}

func download_sizes(oauth OAuth, photo_id string) {

	file_path := get_photo_sizes_path(photo_id)
	if exists(file_path) {
		// fmt.Println("photo_id sizes already exists:", photo_id)
		return
	}
	fmt.Println("Downloading sizes for photo_id:", photo_id)

	// data, _ := json.MarshalIndent(photo_info, "", "    ")
	// ioutil.WriteFile(get_photo_info_path(photo_id), data, 0644)

	params := map[string]string{"photo_id": photo_id}
	page_str := call_method(oauth, "flickr.photos.getSizes", params)

	ioutil.WriteFile(file_path, []byte(page_str), 0644)

}

func get_sizes(oauth OAuth) {

	photo_ids := make(chan string)

	for i := 0; i < SIZES_DOWNLOADERS; i++ {
		go func() {
			for {
				photo_id := <-photo_ids
				if photo_id == "finish" {
					break
				}
				download_sizes(oauth, photo_id)
			}
		}()
	}

	for i := 1; ; i++ {
		file_name := get_photos_path(i)
		if !exists(file_name) {
			// fmt.Println("File doesn't exist:", file_name)
			break
		}

		byte_data, _ := ioutil.ReadFile(file_name)
		str := string(byte_data)
		fmt.Println("Processing sizes. Page", i)

		page_obj := string_to_json(str)

		// convert
		photos_obj, _ := page_obj["photos"].(map[string]interface{})
		photos_lst, _ := photos_obj["photo"].([]interface{})

		for _, photo_info_interface := range photos_lst {
			photo_info := photo_info_interface.(map[string]interface{})
			photo_id := photo_info["id"].(string)

			photo_ids <- photo_id

		}

	}

	fmt.Println("Waiting for downloads")

	for i := 0; i < SIZES_DOWNLOADERS; i++ {
		photo_ids <- "finish"
	}

	fmt.Println("Done. All photo sizes were downloaded")

}

type Size struct {
	Label  string      `json:"label"`
	Width  interface{} `json:"width"`
	Height interface{} `json:"height"`
	Source string      `json:"source"`
	Url    string      `json:"url"`
	Media  string      `json:"media"`
}

type Sizes struct {
	Sizes struct {
		CanBlog     int    `json:"canblog"`
		CanPrint    int    `json:"canprint"`
		CanDownload int    `json:"candownload"`
		Size        []Size `json:"size"`
	} `json:"sizes"`

	Stat string `json:"stat"`
}

type DownloadPhotoMsg struct {
	PhotoId string
	Url     string
}

func download_photos() {

	ch := make(chan DownloadPhotoMsg)

	fmt.Println("Downloading files using", PHOTO_DOWNLOADERS, "workers")

	for i := 0; i < PHOTO_DOWNLOADERS; i++ {
		go func(worker_id int) {
			for {
				msg := <-ch
				if msg.PhotoId == "finish" {
					break
				}

				filename := get_media_location(msg.PhotoId)

				if exists(filename) {
					continue
				}

				resp, err := http.Get(msg.Url)
				if err != nil {
					// handle error
					fmt.Println("Error downloading photo by worker"+strconv.Itoa(worker_id), err)
					continue
				}
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)

				ioutil.WriteFile(filename, body, 0644)
				fmt.Println("worker", worker_id, "downloaded:", msg.PhotoId, filename)

			}
		}(i)
	}

	files, _ := ioutil.ReadDir(get_photos_sizes_metadata_path())
	for _, file_info := range files {

		filename := file_info.Name()

		data, _ := ioutil.ReadFile(get_photos_sizes_metadata_path() + "/" + filename)

		sizes := Sizes{}
		json.Unmarshal(data, &sizes)

		for _, size := range sizes.Sizes.Size {
			if size.Label != "Original" {
				continue
			}

			photo_id := filename[:strings.Index(filename, "-")]
			ch <- DownloadPhotoMsg{
				PhotoId: photo_id,
				Url:     size.Source,
			}

		}

	}

	fmt.Println("Waiting for downloads")

	for i := 0; i < PHOTO_DOWNLOADERS; i++ {
		ch <- DownloadPhotoMsg{PhotoId: "finish"}
	}

	fmt.Println("Done. All photo sizes were downloaded")

}

func main() {
	flag.String("app_key", "", "Application key (provided by Flickr)")
	flag.String("app_secret", "", "Application secret (provided by Flickr)")
	// flag.Parse()
	// flag.Usage()
	options := read_options()
	// key := "9d02801ad8f643e46a3f52ef95e293d0"
	// secret := "2e05dc94d4cdcf21"
	// ask_permissions(key, secret)

	// token := "72157645981882285-501b87a200b3b2af"
	// verifier := "53b56f74b95b7554"
	// token_secret := "4bb6a18c87eb35ef"
	// resp := access_token(key, secret, token, token_secret, verifier)
	// fmt.Println("Resp:", resp)

	// token := "72157645566769998-1b5f6f77dbf2ee7e"
	// token_secret := "3f262cc33e4edbc2"
	// user_id := "60869647%40N05"

	// call_method(key, secret, token, token_secret, user_id, "flickr.people.getPhotos")

	// enc := json.NewEncoder(os.Stdout)
	// out1, _ := json.MarshalIndent(options, "", "    ")
	// os.Stdout.Write(out1)
	// os.Stdout.WriteString("\n")

	// fmt.Println(res)
	// get_all_photos(options)
	// get_sizes(options.OAuth)
	options = options

	download_photos()

	// http.HandleFunc("/", handler)
	// http.ListenAndServe(":18989", nil)

}
