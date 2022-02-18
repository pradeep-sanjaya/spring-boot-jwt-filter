package com.techprovint.interceptor;

import com.techprovint.model.AuditTrail;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
@Slf4j
public class AuditTrailInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(
        HttpServletRequest request,
        HttpServletResponse response,
        Object handler
    ) throws Exception {
        log.info("AuditTrailInterceptor.preHandle");
        AuditTrail auditTrail = null;

        try {
            auditTrail = new AuditTrail(request);
            log.info("auditTrail: {}", auditTrail.toString());
        } catch (Exception e) {
            log.info("exception: {}", e.getMessage());
        }

        return true;

    }

    @Override
    public void postHandle(
        HttpServletRequest request,
        HttpServletResponse response,
        Object handler,
        ModelAndView modelAndView
    ) throws Exception {
        log.info("AuditTrailInterceptor.postHandle");
    }

    @Override
    public void afterCompletion(
        HttpServletRequest request,
        HttpServletResponse response,
        Object handler,
        Exception exception
    ) throws Exception {
        log.info("AuditTrailInterceptor.afterCompletion");
    }
}