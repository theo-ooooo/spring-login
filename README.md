# 🛠️ 로그인 처리 - Cookie, Session, Filter, Interceptor

스프링 MVC에서 로그인 처리를 구현할 때 사용하는 다양한 방법들을 정리합니다.

---

## 1. 쿠키 (Cookie)

### ✅ 개념
- 사용자의 브라우저에 데이터를 저장
- 서버가 클라이언트에게 Set-Cookie 헤더로 전달
- 이후 클라이언트가 요청 시 Cookie 헤더로 전송

### 📌 예제

```java
// 로그인 성공 시 쿠키 저장
Cookie idCookie = new Cookie("memberId", String.valueOf(loginMember.getId()));
response.addCookie(idCookie);
```

```java
// 쿠키 조회
private Cookie findCookie(HttpServletRequest request, String name) {
    if (request.getCookies() == null) {
        return null;
    }
    for (Cookie cookie : request.getCookies()) {
        if (cookie.getName().equals(name)) {
            return cookie;
        }
    }
    return null;
}
```

### ❗ 한계
- 보안 취약 (탈취 가능성 있음)
- 쿠키 조작 가능
- 민감 정보 저장 불가

---

## 2. 세션 (Session)

### ✅ 개념
- 서버에 사용자 정보를 저장
- `HttpSession` 객체 사용
- 클라이언트는 JSESSIONID 쿠키로 세션을 식별

### 📌 예제

```java
// 로그인 성공 시 세션 생성 및 저장
HttpSession session = request.getSession();
session.setAttribute(SessionConst.LOGIN_MEMBER, loginMember);
```

```java
// 세션 조회
Member member = (Member) session.getAttribute(SessionConst.LOGIN_MEMBER);
```

```java
// 로그아웃
HttpSession session = request.getSession(false);
if (session != null) {
    session.invalidate();
}
```

---

## 3. 필터 (Filter)

### ✅ 개념
- Servlet 기반 필터
- DispatcherServlet 호출 전후에 동작
- 인증, 인코딩 등 공통 처리를 담당

### 📌 예제

```java
@WebFilter(urlPatterns = "/*")
public class LoginCheckFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpSession session = httpRequest.getSession(false);

        boolean isLogin = (session != null) && (session.getAttribute(SessionConst.LOGIN_MEMBER) != null);
        if (!isLogin) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.sendRedirect("/login?redirectURL=" + httpRequest.getRequestURI());
            return;
        }

        chain.doFilter(request, response);
    }
}
```

### 📎 필터 등록 (WebConfig)

```java
@Bean
public FilterRegistrationBean loginCheckFilter() {
    FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
    registrationBean.setFilter(new LoginCheckFilter());
    registrationBean.setOrder(1); // 필터 순서
    registrationBean.addUrlPatterns("/*");
    return registrationBean;
}
```

---

## 4. 인터셉터 (Interceptor)

### ✅ 개념
- 스프링 MVC에서 제공하는 인증 처리 도구
- 컨트롤러 호출 전/후에 동작
- `HandlerInterceptor` 인터페이스 구현

### 📌 예제

```java
public class LoginCheckInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute(SessionConst.LOGIN_MEMBER) == null) {
            response.sendRedirect("/login?redirectURL=" + request.getRequestURI());
            return false;
        }
        return true;
    }
}
```

### 📎 인터셉터 등록 (WebConfig)

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new LoginCheckInterceptor())
                .order(1)
                .addPathPatterns("/**")
                .excludePathPatterns("/", "/login", "/logout", "/css/**", "/*.ico", "/error");
    }
}
```

---

## 🔒 쿠키 vs 세션 vs 필터 vs 인터셉터 정리

| 항목        | 특징                                      | 사용 시점              |
|-----------|-----------------------------------------|----------------------|
| 쿠키        | 클라이언트에 저장, 조작 위험 있음                   | 인증 토큰 저장 등        |
| 세션        | 서버에 저장, 보안 좋음                          | 로그인 정보 저장         |
| 필터        | 서블릿 레벨, DispatcherServlet 이전 실행         | 인증/인가, 로깅 등        |
| 인터셉터     | 스프링 MVC 레벨, 컨트롤러 호출 전후 실행          | 로그인 체크, 권한 검증 등 |
