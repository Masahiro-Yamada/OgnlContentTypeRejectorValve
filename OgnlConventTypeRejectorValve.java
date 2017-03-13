package com.github.user.masahiro-yamada.ognlcontenttyperejector;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
/**
 * Valve to reject attack for Struts2 CVE-2017-5638 (S2-045)
 */
public class OgnlContentTypeRejectorValve extends ValveBase {

    /**
     * Default Constructor
     */
    public OgnlContentTypeRejectorValve() {
        //do nothing
    }

    /**
     * Constructor
     * @param asyncSupported
     */
    public OgnlContentTypeRejectorValve(boolean asyncSupported) {
        super(asyncSupported);
    }

    @Override
    public String getInfo() {
        return "OgnlContentTypeRejectorValve/1.0";
    }
    /* (non-Javadoc)
     * @see org.apache.catalina.valves.ValveBase#invoke(org.apache.catalina.connector.Request, org.apache.catalina.connector.Response)
     */
    @Override
    public void invoke(Request request, Response response) throws IOException,
            ServletException {
        final String contentType = request.getContentType();
        // reject when content-Type contains OGNL
        if (contentType != null) {
            if (contentType.contains("%{") || contentType.contains("${")) {
                ((HttpServletResponse)response).sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
        }
        getNext().invoke(request, response);
    }

}
