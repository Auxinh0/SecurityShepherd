package servlets;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Defence-in-depth against CSRF: a state-changing request must carry an Origin or Referer header
 * that matches this application's own origin. A cross-site forged request either omits those
 * headers or carries the attacker's origin, so it is rejected before it reaches a handler.
 */
public class CsrfOriginFilter implements Filter {

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    // no configuration required
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse res = (HttpServletResponse) response;

    String origin = req.getHeader("Origin");
    String referer = req.getHeader("Referer");
    String source = origin != null ? origin : referer;

    if (source == null || !isSameOrigin(req, source)) {
      res.sendError(HttpServletResponse.SC_FORBIDDEN);
      return;
    }

    chain.doFilter(request, response);
  }

  private boolean isSameOrigin(HttpServletRequest request, String source) {
    try {
      URI uri = new URI(source);
      if (uri.getHost() == null || uri.getScheme() == null) {
        return false;
      }
      return request.getScheme().equalsIgnoreCase(uri.getScheme())
          && request.getServerName().equalsIgnoreCase(uri.getHost())
          && getPort(request.getScheme(), request.getServerPort())
              == getPort(uri.getScheme(), uri.getPort());
    } catch (URISyntaxException e) {
      return false;
    }
  }

  private int getPort(String scheme, int port) {
    if (port > 0) {
      return port;
    }
    return "https".equalsIgnoreCase(scheme) ? 443 : 80;
  }

  @Override
  public void destroy() {
    // no resources to release
  }
}
