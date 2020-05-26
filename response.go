// HTTP响应处理

package echo

import (
	"bufio"
	"net"
	"net/http"
)

type (
	// Response wraps an http.ResponseWriter and implements its interface to be used
	// by an HTTP handler to construct an HTTP response.
	// See: https://golang.org/pkg/net/http/#ResponseWriter
	Response struct {                       // 定义响应数据结构
		echo        *Echo                   // echo 对象（服务器等全局数据）
		beforeFuncs []func()                // 响应之前执行的函数
		afterFuncs  []func()                // 响应之后执行的函数
		Writer      http.ResponseWriter     // http.ResponseWriter
		Status      int                     // 响应状态码
		Size        int64                   // 响应内容的数据大小
		Committed   bool                    // HTTP头是否已设置
	}
)

// 创建一个新的响应实现
// NewResponse creates a new instance of Response.
func NewResponse(w http.ResponseWriter, e *Echo) (r *Response) {
	return &Response{Writer: w, echo: e}
}

// 返回将要发送的Header头信息
// Header returns the header map for the writer that will be sent by
// WriteHeader. Changing the header after a call to WriteHeader (or Write) has
// no effect unless the modified headers were declared as trailers by setting
// the "Trailer" header before the call to WriteHeader (see example)
// To suppress implicit response headers, set their value to nil.
// Example: https://golang.org/pkg/net/http/#example_ResponseWriter_trailers
func (r *Response) Header() http.Header {
	return r.Writer.Header()
}

// 添加一个响应之后执行的函数
// Before registers a function which is called just before the response is written.
func (r *Response) Before(fn func()) {
	r.beforeFuncs = append(r.beforeFuncs, fn)
}

// 添加一个响应之前执行的函数
// After registers a function which is called just after the response is written.
// If the `Content-Length` is unknown, none of the after function is executed.
func (r *Response) After(fn func()) {
	r.afterFuncs = append(r.afterFuncs, fn)
}

// 输出响应头信息
// WriteHeader sends an HTTP response header with status code. If WriteHeader is
// not called explicitly, the first call to Write will trigger an implicit
// WriteHeader(http.StatusOK). Thus explicit calls to WriteHeader are mainly
// used to send error codes.
func (r *Response) WriteHeader(code int) {
	// 判断头信息是否已输出
	if r.Committed {
		r.echo.Logger.Warn("response already committed")
		return
	}
	// 执行响应之前执行的函数
	for _, fn := range r.beforeFuncs {
		fn()
	}
	// 记录响应的状态码
	r.Status = code
	// 写入响应码
	r.Writer.WriteHeader(code)
	// 标记头信息已输出
	r.Committed = true
}

// 输出响应主体部分
// Write writes the data to the connection as part of an HTTP reply.
func (r *Response) Write(b []byte) (n int, err error) {
	// 如果没有输出响应头则输出头信息
	if !r.Committed {
		if r.Status == 0 {
			// 默认输出 200 OK
			r.Status = http.StatusOK 
		}
		r.WriteHeader(r.Status)
	}
	// 输出响应主体
	n, err = r.Writer.Write(b)
	// 记录响应主体大小
	r.Size += int64(n)
	// 执行响应之后执行的函数
	for _, fn := range r.afterFuncs {
		fn()
	}
	return
}

// 刷新数据到客户端
// Flush implements the http.Flusher interface to allow an HTTP handler to flush
// buffered data to the client.
// See [http.Flusher](https://golang.org/pkg/net/http/#Flusher)
func (r *Response) Flush() {
	r.Writer.(http.Flusher).Flush()
}

// 获取响应的客户端连接
// Hijack implements the http.Hijacker interface to allow an HTTP handler to
// take over the connection.
// See [http.Hijacker](https://golang.org/pkg/net/http/#Hijacker)
func (r *Response) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return r.Writer.(http.Hijacker).Hijack()
}

// 重置响应
func (r *Response) reset(w http.ResponseWriter) {
	r.beforeFuncs = nil
	r.afterFuncs = nil
	r.Writer = w
	r.Size = 0
	r.Status = http.StatusOK
	r.Committed = false
}
