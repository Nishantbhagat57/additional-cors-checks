@file:Suppress("ObjectPropertyName", "ObjectPropertyName", "ObjectPropertyName")

package burp

import java.awt.Color
import java.util.*

class CorsHelper(private val callbacks: IBurpExtenderCallbacks, private val url: String) {


    private fun cloneIHttpRequestResponse(
        originalRequestResponse: IHttpRequestResponse
    ): IHttpRequestResponse {
        return object : IHttpRequestResponse {
            var _request = originalRequestResponse.request
            var _response = originalRequestResponse.response
            var _comment = originalRequestResponse.comment
            var _highlight = originalRequestResponse.highlight
            var _httpService = originalRequestResponse.httpService
            override fun getRequest(): ByteArray {
                return _request
            }

            override fun setRequest(message: ByteArray) {
                _request = message
            }

            override fun getResponse(): ByteArray {
                return _response
            }

            override fun setResponse(message: ByteArray) {
                _response = message
            }

            override fun getComment(): String {
                return _comment
            }

            override fun setComment(comment: String) {
                this._comment = comment
            }

            override fun getHighlight(): String {
                return _highlight
            }

            override fun setHighlight(color: String) {
                _highlight = color
            }

            override fun getHttpService(): IHttpService {
                return _httpService
            }

            override fun setHttpService(httpService: IHttpService) {
                this._httpService = httpService
            }
        }
    }

    // create array of all Origin header modifications
    private fun corsHeaders(URL: String, BASE_URL: String): Collection<String> {
        val corsHeaderArr = ArrayList<String>()
        corsHeaderArr.add("Origin: https://$URL") // arbitrary reflection
        corsHeaderArr.add("Origin: http://$BASE_URL")  // trust HTTP
        corsHeaderArr.add("Origin: null") // null origin
        corsHeaderArr.add("Origin: https://$BASE_URL.$URL") // prefix match https://vulnerable.com.example.com
        corsHeaderArr.add("Origin: https://$BASE_URL$URL") // suffix match https://vulnerable.comexample.com
        corsHeaderArr.add("Origin: https://subdomain.$BASE_URL") // trust arbitrary subdomain
        corsHeaderArr.add("Origin: https://${BASE_URL.dropLast(1)}") // substring match
        corsHeaderArr.add("Origin: https://localhost$BASE_URL") // https://anythingvulnerable.com & https://localhostvulnerable.com - covers 2 cases
        corsHeaderArr.add("Origin: https://$BASE_URL" + "_.$URL") // underscope bypass 1 https://corben.io/blog/18-6-16-advanced-cors-techniques/ vulnerable.com_.example.com
        corsHeaderArr.add("Origin: https://$BASE_URL" + "._.$URL") // underscope bypass 2 https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet/ vulnerable.com._.example.com
        corsHeaderArr.add("Origin: https://$BASE_URL" + ".&.$URL") // & bypass https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet/ vulnerable.com.&.example.com
        corsHeaderArr.add("Origin: https://localhost.$BASE_URL/") // localhost bypass https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet/ localhost.vulnerable.com/
        corsHeaderArr.add("Origin: http://s$BASE_URL/") // unencrypted domain ends with http://s<allowed>/ https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet/ http://svulnerable.com
        
        // dot not escaped
        if (BASE_URL.count { "." in BASE_URL } > 1) {
            val lastindex = BASE_URL.lastIndexOf(".")
            val url = BASE_URL.substring(0, lastindex).replace(".", "x") + BASE_URL.substring(lastindex)
            corsHeaderArr.add("Origin: https://$url")  // www.example.com -> wwwexample.com

        }
        return corsHeaderArr
    }

    // wrapper to generatecors headrs and execute requests
    fun generateCorsRequests(messageInfo: IHttpRequestResponse): Collection<IHttpRequestResponse> {
        val corsRequests = ArrayList<IHttpRequestResponse>()

        val analyzedRequest = callbacks.helpers.analyzeRequest(messageInfo)

        val baseUrl = messageInfo.httpService.host

        for (corsHeader in corsHeaders(url, baseUrl)) {
            val newReq = cloneIHttpRequestResponse(messageInfo)
            performCorsRequests(newReq, corsHeader, analyzedRequest)?.let { corsRequests.add(it) }
        }

        return corsRequests
    }

    // execute all cors requests for the original request
    private fun performCorsRequests(
        newReq: IHttpRequestResponse?,
        corsHeader: String,
        analyzedRequest: IRequestInfo
    ): IHttpRequestResponse? {
        val headers = analyzedRequest.headers
        val newHeaders = headers?.let { generateNewHeaders(it, corsHeader) }

        val message = callbacks.helpers.buildHttpMessage(newHeaders,
            newReq?.request?.let { Arrays.copyOfRange(newReq.request, analyzedRequest.bodyOffset, it.size) })
        newReq?.request = message

        return callbacks.makeHttpRequest(newReq?.httpService, newReq?.request)
    }

    private fun generateNewHeaders(headers: List<String>, corsHeader: String): ArrayList<String> {

        //check if origin header already present
        val newHeaders = ArrayList<String>()
        for (header in headers) {
            if (!header.contains("Origin:")) {
                newHeaders.add(header)
            }
        }
        newHeaders.add(corsHeader)
        return newHeaders
    }

    // returns color of a response
    fun evaluateColor(requestResponse: IHttpRequestResponse, urlWithProto: String): Color? {
        val request = callbacks.helpers.analyzeRequest(requestResponse.request)

        // the response can be null. If so, ignore.
        if(requestResponse.response == null) {
            return null
        }

        if(request.method.equals("OPTIONS", ignoreCase = true)){
            return null
        }

        val response: IResponseInfo? = callbacks.helpers.analyzeResponse(requestResponse.response)

        var acac = false
        var acao = false
        var origin: String? = null

        // get origin
        for (reqHeader in request!!.headers) {
            if (reqHeader.startsWith("Origin:", ignoreCase = true)) {
                origin = reqHeader.substringAfter(":")
            }
        }

        // check if ACAC and/or ACAO are set
        for (respHeader in response!!.headers) {
            if (respHeader.contains("Access-Control-Allow-Credentials: true", ignoreCase = true)) {
                acac = true
            } else if (origin != null && respHeader.replace(" ", "")
                    .contains("Access-Control-Allow-Origin: $origin".replace(" ", ""), ignoreCase = true)
            ) {
                if(origin != urlWithProto) {
                    acao = true
                }
            }
        }

        return if (acac && acao) {
            Color.RED
        } else if (acao) {
            Color.YELLOW
        } else {
            null
        }
    }
}
