package main

import "bytes"
import "crypto/hmac"
import "crypto/sha1"
import "encoding/base64"
import "fmt"
import "io/ioutil"
import "math/rand"
import "net/http"
import "net/url"
import "sort"
import "strconv"
import "strings"
import "time"

const METHOD_GET = "GET"
const API_KEY = "..."

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

func calculate_signature(method, url, consumer_secret, token_secret string, params map[string]string) string {

	// buffer to generate the output
	var buffer bytes.Buffer

	// write the method in uppercase
	buffer.WriteString(strings.ToUpper(method))
	buffer.WriteString("&")

	// write the url
	buffer.WriteString(escape(url))
	buffer.WriteString("&")

	// write the parameter string
	param_str := parameter_string(params)
	buffer.WriteString(escape(param_str))

	text_to_sign := buffer.String()

	// calculate signature
	byte_key := []byte(consumer_secret + "&" + token_secret)
	hasher := hmac.New(sha1.New, byte_key)
	hasher.Write([]byte(text_to_sign))

	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))

}

func random_nonce() string {
	return strconv.Itoa(rand.Int())
}

func timestamp() string {
	return string(time.Now().Unix())
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
	body := generic_call(base_url, key, secret, "", params)
	return params_to_map(body)
}

func generic_call(base_url, key, secret, token_secret string, params map[string]string) string {

	effective_params := map[string]string{}
	for key, value := range params {
		effective_params[key] = value
	}
	add_oauth_params(key, effective_params)

	signature := calculate_signature(METHOD_GET, base_url, secret, token_secret, effective_params)
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

func access_token(key, secret, token, token_secret, verifier string) map[string]string {

	params := add_oauth_params(key, map[string]string{
		"oauth_token":    token,
		"oauth_verifier": verifier,
	})

	base_url := "https://www.flickr.com/services/oauth/access_token"

	body := generic_call(base_url, key, secret, token_secret, params)

	return params_to_map(body)

}

func call_method(key, secret, token, token_secret, user_id, method string) string {

	params := add_oauth_params(key, map[string]string{
		"format":         "json",
		"nojsoncallback": "1",
		"method":         method,
		"user_id":        user_id,
		"oauth_token":    token,
	})

	base_url := "https://api.flickr.com/services/rest"

	body := generic_call(base_url, key, secret, token_secret, params)

	fmt.Println(body)
	return body

}

func main() {
	// key := "..."
	// secret := "..."
	// ask_permissions(key, secret) // first run

	// token := "..."
	// verifier := "..."
	// token_secret := "..."
	// resp := access_token(key, secret, token, token_secret, verifier)
	// fmt.Println("Resp:", resp)

	// token := "..."
	// token_secret := "..."
	// user_id := "..."

	// call_method(key, secret, token, token_secret, user_id, "flickr.people.getPhotos")

}
