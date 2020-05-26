// 定义路由分组
// 可以按Host进行分组，也可按前缀进行分组

package echo

import (
	"net/http"
)

type (
	// Group is a set of sub-routes for a specified route. It can be used for inner
	// routes that share a common middleware or functionality that should be separate
	// from the parent echo instance while still inheriting from it.
	Group struct {
		common                        // 空的结构体，公用
		host       string             // 域名Host
		prefix     string             // 前缀
		middleware []MiddlewareFunc   // 中间件
		echo       *Echo              // 服务器实例（全局资源）
	}
)

// 分组使用某个中间件
// Use implements `Echo#Use()` for sub-routes within the Group.
func (g *Group) Use(middleware ...MiddlewareFunc) {
	g.middleware = append(g.middleware, middleware...)
	if len(g.middleware) == 0 {
		return
	}
	// Allow all requests to reach the group as they might get dropped if router
	// doesn't find a match, making none of the group middleware process.
	g.Any("", NotFoundHandler)
	g.Any("/*", NotFoundHandler)
}

// 分组增加 CONNECT 方法的对应中间件
// CONNECT implements `Echo#CONNECT()` for sub-routes within the Group.
func (g *Group) CONNECT(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return g.Add(http.MethodConnect, path, h, m...)
}

// 分组增加 DELETE 方法的对应中间件
// DELETE implements `Echo#DELETE()` for sub-routes within the Group.
func (g *Group) DELETE(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return g.Add(http.MethodDelete, path, h, m...)
}

// 分组增加 GET 方法的对应中间件
// GET implements `Echo#GET()` for sub-routes within the Group.
func (g *Group) GET(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return g.Add(http.MethodGet, path, h, m...)
}

// 分组增加 HEAD 方法的对应中间件
// HEAD implements `Echo#HEAD()` for sub-routes within the Group.
func (g *Group) HEAD(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return g.Add(http.MethodHead, path, h, m...)
}

// 分组增加 OPTIONS 方法的对应中间件
// OPTIONS implements `Echo#OPTIONS()` for sub-routes within the Group.
func (g *Group) OPTIONS(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return g.Add(http.MethodOptions, path, h, m...)
}

// 分组增加 PATCH 方法的对应中间件
// PATCH implements `Echo#PATCH()` for sub-routes within the Group.
func (g *Group) PATCH(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return g.Add(http.MethodPatch, path, h, m...)
}

// 分组增加 POST 方法的对应中间件
// POST implements `Echo#POST()` for sub-routes within the Group.
func (g *Group) POST(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return g.Add(http.MethodPost, path, h, m...)
}

// 分组增加 PUT 方法的对应中间件
// PUT implements `Echo#PUT()` for sub-routes within the Group.
func (g *Group) PUT(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return g.Add(http.MethodPut, path, h, m...)
}

// 分组增加 TRACE 方法的对应中间件
// TRACE implements `Echo#TRACE()` for sub-routes within the Group.
func (g *Group) TRACE(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return g.Add(http.MethodTrace, path, h, m...)
}

// 分组增加 所有请求方法的对应中间件
// Any implements `Echo#Any()` for sub-routes within the Group.
func (g *Group) Any(path string, handler HandlerFunc, middleware ...MiddlewareFunc) []*Route {
	routes := make([]*Route, len(methods))
	for i, m := range methods {
		routes[i] = g.Add(m, path, handler, middleware...)
	}
	return routes
}

// 分组增加 指定请求方法的对应中间件
// Match implements `Echo#Match()` for sub-routes within the Group.
func (g *Group) Match(methods []string, path string, handler HandlerFunc, middleware ...MiddlewareFunc) []*Route {
	routes := make([]*Route, len(methods))
	for i, m := range methods {
		routes[i] = g.Add(m, path, handler, middleware...)
	}
	return routes
}

// 返回分组
// Group creates a new sub-group with prefix and optional sub-group-level middleware.
func (g *Group) Group(prefix string, middleware ...MiddlewareFunc) (sg *Group) {
	m := make([]MiddlewareFunc, 0, len(g.middleware)+len(middleware))
	m = append(m, g.middleware...)
	m = append(m, middleware...)
	sg = g.echo.Group(g.prefix+prefix, m...)
	sg.host = g.host
	return
}

// 分组静态处理
// Static implements `Echo#Static()` for sub-routes within the Group.
func (g *Group) Static(prefix, root string) {
	// 调用 common.static
	g.static(prefix, root, g.GET)
}

// 分组文件处理
// File implements `Echo#File()` for sub-routes within the Group.
func (g *Group) File(path, file string) {
	// 调用 common.file
	g.file(g.prefix+path, file, g.GET)
}

// 分组注册一个指定请求方法的路由
// Add implements `Echo#Add()` for sub-routes within the Group.
func (g *Group) Add(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Route {
	// Combine into a new slice to avoid accidentally passing the same slice for
	// multiple routes, which would lead to later add() calls overwriting the
	// middleware from earlier calls.
	m := make([]MiddlewareFunc, 0, len(g.middleware)+len(middleware))
	m = append(m, g.middleware...)
	m = append(m, middleware...)
	return g.echo.add(g.host, method, g.prefix+path, handler, m...)
}
