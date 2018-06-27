package tifgo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	opt    *Options
	client *http.Client
)

// Options ...
type Options struct {
	Hosts           []string
	PaasID          string
	PaasToken       string
	MaxRetries      int
	TimeOffsetLimit int64
}

// Init ...
func Init(options *Options) {
	opt = options
	if opt.TimeOffsetLimit == 0 {
		opt.TimeOffsetLimit = 180
	}
	client = &http.Client{}
}

// Request tif request
type Request struct {
	req     *http.Request
	res     *http.Response
	header  map[string]string
	reqbody []byte
	resbody []byte
	method  string
}

func getHost() string {
	return opt.Hosts[rand.Intn(len(opt.Hosts))]
}

// New ...
func New() (r *Request) {
	return &Request{
		method: "GET",
	}
}

// GetResp return request resp
func (r *Request) GetResp() *http.Response {
	return r.res
}

// GetBody return request resp body
func (r *Request) GetBody() []byte {
	return r.resbody
}

// SetHeader set header
func (r *Request) SetHeader(k, v string) *Request {
	r.header[k] = v
	return r
}

// Send ...
func (r *Request) Send(data interface{}) *Request {
	r.reqbody, _ = json.Marshal(data)
	return r
}

// Do ...
func (r *Request) Do(path string, result interface{}) (err error) {
	url := getHost() + path
	if r.req, err = http.NewRequest(r.method, url, bytes.NewBuffer(r.reqbody)); err != nil {
		return
	}
	addGateHeader(r.req)
	for k, v := range r.header {
		r.req.Header.Add(k, v)
	}
	if r.res, err = client.Do(r.req); err != nil {
		return
	}
	defer r.res.Body.Close()
	if r.res.StatusCode != http.StatusOK {
		return fmt.Errorf("http status=%d content=%s", r.res.StatusCode, string(r.resbody))
	}
	if r.resbody, err = ioutil.ReadAll(r.res.Body); err != nil {
		return
	}
	if err = json.Unmarshal(r.resbody, result); err != nil {
		return fmt.Errorf("json parse fail %s", err.Error())
	}
	return
}

// APIResult ...
type APIResult struct {
	Errcode int         `json:"errcode"`
	Errmsg  string      `json:"errmsg"`
	Data    interface{} `json:"data"`
}

// DoAPI ...
func (r *Request) DoAPI(path string, result interface{}) (err error) {
	ar := &APIResult{
		Data: result,
	}
	if err = r.Do(path, result); err != nil {
		return
	}
	if ar.Errcode != 0 {
		return fmt.Errorf("errcode=%d errmsg=%s", ar.Errcode, ar.Errmsg)
	}
	return
}

func addGateHeader(r *http.Request) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := GenerateRandomStringHex(10)
	signData := fmt.Sprintf("%s%s%s%s", ts, opt.PaasToken, nonce, ts)
	signstr := strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256([]byte(signData))))
	r.Header.Add("X-Tif-Paasid", opt.PaasID)
	r.Header.Add("X-Tif-Timestamp", ts)
	r.Header.Add("X-Tif-Nonce", nonce)
	r.Header.Add("X-Tif-Signature", signstr)
}

// AuthSign auth tif http header sign
func AuthSign(r *http.Request) error {
	uid := r.Header.Get("X-Tif-Uid")
	uinfo := r.Header.Get("X-Tif-Uinfo")
	ext := r.Header.Get("X-Tif-Ext")
	ts := r.Header.Get("X-Tif-Timestamp")
	nonce := r.Header.Get("X-Tif-Nonce")
	sign := r.Header.Get("X-Tif-Signature")

	t, _ := strconv.ParseInt(ts, 10, 64)
	now := time.Now().Unix()
	if t < now-opt.TimeOffsetLimit || t > now+opt.TimeOffsetLimit {
		return fmt.Errorf("Header time offset exceeded limit, timestamp=%s now=%d", ts, now)
	}
	var signData string
	if uid != "" {
		signData = fmt.Sprintf("%s%s%s,%s,%s,%s%s", ts, opt.PaasToken, nonce, uid, uinfo, ext, ts)
	} else {
		signData = fmt.Sprintf("%s%s%s%s", ts, opt.PaasToken, nonce, ts)
	}
	res := strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256([]byte(signData))))
	if res == sign {
		return nil
	}
	err := fmt.Errorf("signature invalid, uid=%s uinfo=%s ext=%s timestamp=%s nonce=%s signature=%s",
		uid, uinfo, ext, ts, nonce, sign)
	return err
}

// GenerateRandomBytes returns securely generated random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomStringHex random string hex
func GenerateRandomStringHex(s int) string {
	b, _ := GenerateRandomBytes(s)
	return hex.EncodeToString(b)
}
