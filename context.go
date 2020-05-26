// 请求上下文对象
// 对请求、输出 两个过程中的数据和方法进行封装

package echo

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type (
	// Context represents the context of the current HTTP request. It holds request and
	// response objects, path, path parameters, data and registered handler.
	Context interface {
		// 获取上下文中的请求信息
		// Request returns `*http.Request`.
		Request() *http.Request

		// 设置上下文中的请求信息
		// SetRequest sets `*http.Request`.
		SetRequest(r *http.Request)

		// 获取上下文中的响应信息
		// Response returns `*Response`.
		Response() *Response
		
		// 上下文中的链接是否是TLS连接
		// IsTLS returns true if HTTP connection is TLS otherwise false.
		IsTLS() bool

		// 上下文中的链接是否是WebSocket连接
		// IsWebSocket returns true if HTTP connection is WebSocket otherwise false.
		IsWebSocket() bool

		// 上下文中的协议类型
		// Scheme returns the HTTP protocol scheme, `http` or `https`.
		Scheme() string

		// 上下文中的客户端真实IP
		// RealIP returns the client's network address based on `X-Forwarded-For`
		// or `X-Real-IP` request header.
		RealIP() string

		// 上下文中的请求的Path
		// Path returns the registered path for the handler.
		Path() string

		// 设置上下文中的Path
		// SetPath sets the registered path for the handler.
		SetPath(p string)

		// 根据参数名称获取上下文中的参数
		// Param returns path parameter by name.
		Param(name string) string

		// 上下文中的所有参数名称
		// ParamNames returns path parameter names.
		ParamNames() []string

		// 设置上下文中的参数名称
		// SetParamNames sets path parameter names.
		SetParamNames(names ...string)

		// 上下文中的所有参数值
		// ParamValues returns path parameter values.
		ParamValues() []string

		// 设置上下文中的参数值
		// SetParamValues sets path parameter values.
		SetParamValues(values ...string)

		// 根据参数名称获取上下文中的查询参数值
		// QueryParam returns the query param for the provided name.
		QueryParam(name string) string

		// 获取上下文中的所有查询参数
		// QueryParams returns the query parameters as `url.Values`.
		QueryParams() url.Values

		// 获取上下文中的查询字符串
		// QueryString returns the URL query string.
		QueryString() string

		// 根据表单名称获取上下文中的表单值
		// FormValue returns the form field value for the provided name.
		FormValue(name string) string

		// 获取上下文中的所有表单数据
		// FormParams returns the form parameters as `url.Values`.
		FormParams() (url.Values, error)

		// 根据名称获取上下文中的表单文件数据
		// FormFile returns the multipart form file for the provided name.
		FormFile(name string) (*multipart.FileHeader, error)

		// 获取上下文中的多表单
		// MultipartForm returns the multipart form.
		MultipartForm() (*multipart.Form, error)

		// 根据名称获取上下文中的Cookie数据
		// Cookie returns the named cookie provided in the request.
		Cookie(name string) (*http.Cookie, error)

		// 设置上下文中的Cookie数据
		// SetCookie adds a `Set-Cookie` header in HTTP response.
		SetCookie(cookie *http.Cookie)

		// 获取上下文中的所有Cookie数据
		// Cookies returns the HTTP cookies sent with the request.
		Cookies() []*http.Cookie

		// 获取上下文中的属性信息
		// Get retrieves data from the context.
		Get(key string) interface{}

		// 设置上下文中的属性信息
		// Set saves data in the context.
		Set(key string, val interface{})

		// 上下文中的请求body绑定到数据结构上
		// Bind binds the request body into provided type `i`. The default binder
		// does it based on Content-Type header.
		Bind(i interface{}) error

        // 上下文中的验证，一般在Bind后进行调用
		// Validate validates provided `i`. It is usually called after `Context#Bind()`.
		// Validator must be registered using `Echo#Validator`.
		Validate(i interface{}) error
	
		// 上下文中的数据呈现模板，需要Echo.Renderer注册
		// Render renders a template with data and sends a text/html response with status
		// code. Renderer must be registered using `Echo.Renderer`.
		Render(code int, name string, data interface{}) error

		// HTML响应
		// HTML sends an HTTP response with status code.
		HTML(code int, html string) error

		// HTML响应
		// HTMLBlob sends an HTTP blob response with status code.
		HTMLBlob(code int, b []byte) error

		// Text响应
		// String sends a string response with status code.
		String(code int, s string) error

		// JSON响应
		// JSON sends a JSON response with status code.
		JSON(code int, i interface{}) error

		// 漂亮的JOSN响应（自定义缩进字符）
		// JSONPretty sends a pretty-print JSON with status code.
		JSONPretty(code int, i interface{}, indent string) error

		// JSONBlob sends a JSON blob response with status code.
		JSONBlob(code int, b []byte) error

		// JSONP响应
		// JSONP sends a JSONP response with status code. It uses `callback` to construct
		// the JSONP payload.
		JSONP(code int, callback string, i interface{}) error

		// JSONPBlob sends a JSONP blob response with status code. It uses `callback`
		// to construct the JSONP payload.
		JSONPBlob(code int, callback string, b []byte) error

		// XML sends an XML response with status code.
		XML(code int, i interface{}) error

		// XMLPretty sends a pretty-print XML with status code.
		XMLPretty(code int, i interface{}, indent string) error

		// XMLBlob sends an XML blob response with status code.
		XMLBlob(code int, b []byte) error

		// 二进制类型的大对象 响应
		// Blob sends a blob response with status code and content type.
		Blob(code int, contentType string, b []byte) error

		// 数据流响应
		// Stream sends a streaming response with status code and content type.
		Stream(code int, contentType string, r io.Reader) error

		// 文件响应
		// File sends a response with the content of the file.
		File(file string) error

		// 文件 附件响应
		// Attachment sends a response as attachment, prompting client to save the
		// file.
		Attachment(file string, name string) error

		// 文件 内联响应
		// Inline sends a response as inline, opening the file in the browser.
		Inline(file string, name string) error

		// 只有响应头无响应体的响应
		// NoContent sends a response with no body and a status code.
		NoContent(code int) error

		// 转向响应
		// Redirect redirects the request to a provided URL with status code.
		Redirect(code int, url string) error

		// 错误
		// Error invokes the registered HTTP error handler. Generally used by middleware.
		Error(err error)

		// 获取上下文的处理程序
		// Handler returns the matched handler by router.
		Handler() HandlerFunc

		// 设置上下文的处理程序
		// SetHandler sets the matched handler by router.
		SetHandler(h HandlerFunc)

		// 获取日期器对象实例
		// Logger returns the `Logger` instance.
		Logger() Logger

		// 获取服务器等全局对象实例
		// Echo returns the `Echo` instance.
		Echo() *Echo

		// 重置一个请求上下文
		// Reset resets the context after request completes. It must be called along
		// with `Echo#AcquireContext()` and `Echo#ReleaseContext()`.
		// See `Echo#ServeHTTP()`
		Reset(r *http.Request, w http.ResponseWriter)
	}

	// 定义请求上下文数据结构
	// 并通过方法实现了 Context 接口
	context struct {
		request  *http.Request    // 请求
		response *Response        // 响应
		path     string           // 请求 - 路径
		pnames   []string         // 参数名
		pvalues  []string         // 参数值
		query    url.Values       // 查询变量
		handler  HandlerFunc      // 处理句柄
		store    Map              // 存储数据（响应过程中产生的数据）
		echo     *Echo            // 服务器对象（全局类的数据）
		lock     sync.RWMutex     // 存储数据（读写锁）
	}
)

const (
	defaultMemory = 32 << 20      // 默认 32 MB 内存用于解析Form表单（MultipartForm）数据
	indexPage     = "index.html"  // 默认响应文件（静态文件响应）
	defaultIndent = "  "          // 默认缩进2个空格字符（用于JSON和XML的响应内容缩进）
)

// 响应头中写ContentType（网络文件的类型和网页的编码）
func (c *context) writeContentType(value string) {
	header := c.Response().Header()
	if header.Get(HeaderContentType) == "" {
		header.Set(HeaderContentType, value)
	}
}

func (c *context) Request() *http.Request {
	return c.request
}

func (c *context) SetRequest(r *http.Request) {
	c.request = r
}

func (c *context) Response() *Response {
	return c.response
}

func (c *context) IsTLS() bool {
	return c.request.TLS != nil
}

func (c *context) IsWebSocket() bool {
	upgrade := c.request.Header.Get(HeaderUpgrade)
	return strings.ToLower(upgrade) == "websocket"
}

func (c *context) Scheme() string {
	// Can't use `r.Request.URL.Scheme`
	// See: https://groups.google.com/forum/#!topic/golang-nuts/pMUkBlQBDF0
	if c.IsTLS() {
		return "https"
	}
	if scheme := c.request.Header.Get(HeaderXForwardedProto); scheme != "" {
		return scheme
	}
	if scheme := c.request.Header.Get(HeaderXForwardedProtocol); scheme != "" {
		return scheme
	}
	if ssl := c.request.Header.Get(HeaderXForwardedSsl); ssl == "on" {
		return "https"
	}
	if scheme := c.request.Header.Get(HeaderXUrlScheme); scheme != "" {
		return scheme
	}
	return "http"
}

func (c *context) RealIP() string {
	if ip := c.request.Header.Get(HeaderXForwardedFor); ip != "" {
		return strings.Split(ip, ", ")[0]
	}
	if ip := c.request.Header.Get(HeaderXRealIP); ip != "" {
		return ip
	}
	ra, _, _ := net.SplitHostPort(c.request.RemoteAddr)
	return ra
}

func (c *context) Path() string {
	return c.path
}

func (c *context) SetPath(p string) {
	c.path = p
}

func (c *context) Param(name string) string {
	for i, n := range c.pnames {
		if i < len(c.pvalues) {
			if n == name {
				return c.pvalues[i]
			}
		}
	}
	return ""
}

func (c *context) ParamNames() []string {
	return c.pnames
}

func (c *context) SetParamNames(names ...string) {
	c.pnames = names
}

func (c *context) ParamValues() []string {
	return c.pvalues[:len(c.pnames)]
}

func (c *context) SetParamValues(values ...string) {
	c.pvalues = values
}

func (c *context) QueryParam(name string) string {
	if c.query == nil {
		c.query = c.request.URL.Query()
	}
	return c.query.Get(name)
}

func (c *context) QueryParams() url.Values {
	if c.query == nil {
		c.query = c.request.URL.Query()
	}
	return c.query
}

func (c *context) QueryString() string {
	return c.request.URL.RawQuery
}

func (c *context) FormValue(name string) string {
	return c.request.FormValue(name)
}

func (c *context) FormParams() (url.Values, error) {
	if strings.HasPrefix(c.request.Header.Get(HeaderContentType), MIMEMultipartForm) {
		if err := c.request.ParseMultipartForm(defaultMemory); err != nil {
			return nil, err
		}
	} else {
		if err := c.request.ParseForm(); err != nil {
			return nil, err
		}
	}
	return c.request.Form, nil
}

func (c *context) FormFile(name string) (*multipart.FileHeader, error) {
	_, fh, err := c.request.FormFile(name)
	return fh, err
}

func (c *context) MultipartForm() (*multipart.Form, error) {
	err := c.request.ParseMultipartForm(defaultMemory)
	return c.request.MultipartForm, err
}

func (c *context) Cookie(name string) (*http.Cookie, error) {
	return c.request.Cookie(name)
}

func (c *context) SetCookie(cookie *http.Cookie) {
	http.SetCookie(c.Response(), cookie)
}

func (c *context) Cookies() []*http.Cookie {
	return c.request.Cookies()
}

func (c *context) Get(key string) interface{} {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.store[key]
}

func (c *context) Set(key string, val interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.store == nil {
		c.store = make(Map)
	}
	c.store[key] = val
}

func (c *context) Bind(i interface{}) error {
	return c.echo.Binder.Bind(i, c)
}

func (c *context) Validate(i interface{}) error {
	if c.echo.Validator == nil {
		return ErrValidatorNotRegistered
	}
	return c.echo.Validator.Validate(i)
}

func (c *context) Render(code int, name string, data interface{}) (err error) {
	if c.echo.Renderer == nil {
		return ErrRendererNotRegistered
	}
	buf := new(bytes.Buffer)
	if err = c.echo.Renderer.Render(buf, name, data, c); err != nil {
		return
	}
	return c.HTMLBlob(code, buf.Bytes())
}

func (c *context) HTML(code int, html string) (err error) {
	return c.HTMLBlob(code, []byte(html))
}

func (c *context) HTMLBlob(code int, b []byte) (err error) {
	return c.Blob(code, MIMETextHTMLCharsetUTF8, b)
}

func (c *context) String(code int, s string) (err error) {
	return c.Blob(code, MIMETextPlainCharsetUTF8, []byte(s))
}

// JSONP大对象响应
func (c *context) jsonPBlob(code int, callback string, i interface{}) (err error) {
	enc := json.NewEncoder(c.response)
	_, pretty := c.QueryParams()["pretty"]
	if c.echo.Debug || pretty {
		enc.SetIndent("", "  ")
	}
	c.writeContentType(MIMEApplicationJavaScriptCharsetUTF8)
	c.response.WriteHeader(code)
	if _, err = c.response.Write([]byte(callback + "(")); err != nil {
		return
	}
	if err = enc.Encode(i); err != nil {
		return
	}
	if _, err = c.response.Write([]byte(");")); err != nil {
		return
	}
	return
}

// JSON响应
func (c *context) json(code int, i interface{}, indent string) error {
	enc := json.NewEncoder(c.response)
	if indent != "" {
		enc.SetIndent("", indent)
	}
	c.writeContentType(MIMEApplicationJSONCharsetUTF8)
	c.response.Status = code
	return enc.Encode(i)
}

func (c *context) JSON(code int, i interface{}) (err error) {
	indent := ""
	if _, pretty := c.QueryParams()["pretty"]; c.echo.Debug || pretty {
		indent = defaultIndent
	}
	return c.json(code, i, indent)
}

func (c *context) JSONPretty(code int, i interface{}, indent string) (err error) {
	return c.json(code, i, indent)
}

func (c *context) JSONBlob(code int, b []byte) (err error) {
	return c.Blob(code, MIMEApplicationJSONCharsetUTF8, b)
}

func (c *context) JSONP(code int, callback string, i interface{}) (err error) {
	return c.jsonPBlob(code, callback, i)
}

func (c *context) JSONPBlob(code int, callback string, b []byte) (err error) {
	c.writeContentType(MIMEApplicationJavaScriptCharsetUTF8)
	c.response.WriteHeader(code)
	if _, err = c.response.Write([]byte(callback + "(")); err != nil {
		return
	}
	if _, err = c.response.Write(b); err != nil {
		return
	}
	_, err = c.response.Write([]byte(");"))
	return
}

func (c *context) xml(code int, i interface{}, indent string) (err error) {
	c.writeContentType(MIMEApplicationXMLCharsetUTF8)
	c.response.WriteHeader(code)
	enc := xml.NewEncoder(c.response)
	if indent != "" {
		enc.Indent("", indent)
	}
	if _, err = c.response.Write([]byte(xml.Header)); err != nil {
		return
	}
	return enc.Encode(i)
}

func (c *context) XML(code int, i interface{}) (err error) {
	indent := ""
	if _, pretty := c.QueryParams()["pretty"]; c.echo.Debug || pretty {
		indent = defaultIndent
	}
	return c.xml(code, i, indent)
}

func (c *context) XMLPretty(code int, i interface{}, indent string) (err error) {
	return c.xml(code, i, indent)
}

func (c *context) XMLBlob(code int, b []byte) (err error) {
	c.writeContentType(MIMEApplicationXMLCharsetUTF8)
	c.response.WriteHeader(code)
	if _, err = c.response.Write([]byte(xml.Header)); err != nil {
		return
	}
	_, err = c.response.Write(b)
	return
}

func (c *context) Blob(code int, contentType string, b []byte) (err error) {
	c.writeContentType(contentType)
	c.response.WriteHeader(code)
	_, err = c.response.Write(b)
	return
}

func (c *context) Stream(code int, contentType string, r io.Reader) (err error) {
	c.writeContentType(contentType)
	c.response.WriteHeader(code)
	_, err = io.Copy(c.response, r)
	return
}

func (c *context) File(file string) (err error) {
	f, err := os.Open(file)
	if err != nil {
		return NotFoundHandler(c)
	}
	defer f.Close()

	fi, _ := f.Stat()
	if fi.IsDir() {
		file = filepath.Join(file, indexPage)
		f, err = os.Open(file)
		if err != nil {
			return NotFoundHandler(c)
		}
		defer f.Close()
		if fi, err = f.Stat(); err != nil {
			return
		}
	}
	http.ServeContent(c.Response(), c.Request(), fi.Name(), fi.ModTime(), f)
	return
}

func (c *context) Attachment(file, name string) error {
	return c.contentDisposition(file, name, "attachment")
}

func (c *context) Inline(file, name string) error {
	return c.contentDisposition(file, name, "inline")
}

func (c *context) contentDisposition(file, name, dispositionType string) error {
	c.response.Header().Set(HeaderContentDisposition, fmt.Sprintf("%s; filename=%q", dispositionType, name))
	return c.File(file)
}

func (c *context) NoContent(code int) error {
	c.response.WriteHeader(code)
	return nil
}

func (c *context) Redirect(code int, url string) error {
	if code < 300 || code > 308 {
		return ErrInvalidRedirectCode
	}
	c.response.Header().Set(HeaderLocation, url)
	c.response.WriteHeader(code)
	return nil
}

func (c *context) Error(err error) {
	c.echo.HTTPErrorHandler(err, c)
}

func (c *context) Echo() *Echo {
	return c.echo
}

func (c *context) Handler() HandlerFunc {
	return c.handler
}

func (c *context) SetHandler(h HandlerFunc) {
	c.handler = h
}

func (c *context) Logger() Logger {
	return c.echo.Logger
}

func (c *context) Reset(r *http.Request, w http.ResponseWriter) {
	c.request = r
	c.response.reset(w)
	c.query = nil
	c.handler = NotFoundHandler
	c.store = nil
	c.path = ""
	c.pnames = nil
	// NOTE: Don't reset because it has to have length c.echo.maxParam at all times
	// c.pvalues = nil
}
