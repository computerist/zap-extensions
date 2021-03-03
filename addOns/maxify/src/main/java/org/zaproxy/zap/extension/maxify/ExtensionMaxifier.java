/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.zaproxy.zap.extension.maxify;

import java.io.*;
import java.util.*;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.io.IOUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.network.HttpResponseBody;

class LibInfo {
    String name;
    String minSha256Digest;
    String maxSha256Digest;
    String minURI;
    String maxURI;
}

public class ExtensionMaxifier extends ExtensionAdaptor implements ProxyListener {
    private static final String NAME = "Maxify";
    private static final String PREFIX = "maxify";
    private static final String MAXIFY_JSON = "maxify/maxify.json";

    private Map<String, LibInfo> libsByFilename;

    public ExtensionMaxifier() {
        super(NAME);
        setI18nPrefix(PREFIX);

        this.libsByFilename = new HashMap<>();

        try {
            File configFile = new File(Constant.getZapHome(), MAXIFY_JSON);
            FileInputStream fis = new FileInputStream(configFile);
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            IOUtils.copy(fis, os);
            String json = new String(os.toByteArray());

            JSONObject jsonObject = JSONObject.fromObject( json );
            JSONArray libs  = (JSONArray) jsonObject.get("libraries");

            for (Object libObj: libs) {
                JSONObject lib = (JSONObject) libObj;

                LibInfo libInfo = new LibInfo();
                libInfo.name = lib.getString("name");
                libInfo.minURI = lib.getString("minURI");
                libInfo.minSha256Digest = lib.getString("minSha256Digest");
                libInfo.maxURI = lib.getString("maxURI");
                libInfo.maxSha256Digest = lib.getString("maxSha256Digest");
                this.libsByFilename.put(libInfo.name, libInfo);
            }

            fis.close();
            os.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // As long as we're not running as a daemon
        if (getView() != null) {
            extensionHook.getProxyListenerList().add(this);
        }
    }

    @Override
    public int getArrangeableListenerOrder() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        // TODO Auto-generated method stub
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        System.out.println("onHttpResponseReceive");
        try {
            HttpResponseBody body = msg.getResponseBody();
            URI requestURI = msg.getRequestHeader().getURI();
            String path = requestURI.getPath();
            int sepPos = path.lastIndexOf('/');
            String filename = sepPos >= 0 ? path.substring(sepPos + 1) : path;
            if (this.libsByFilename.containsKey(filename)) {
                LibInfo libInfo = this.libsByFilename.get(filename);
                String digestString = DigestUtils.sha256Hex(body.getBytes());

                // We can compare the served version with the expected digest of the minified script
                if (digestString.equals(libInfo.minSha256Digest)) {
                    System.out.println("Minified script digests match!");
                } else {
                    System.out.println("Expected: " + libInfo.minSha256Digest);
                    System.out.println("Got: " + digestString);
                }

                // And then return the un-minified version
                final HttpMessage msg2 = new HttpMessage(new URI(libInfo.maxURI, true));
                HttpSender httpSender =
                        new HttpSender(
                                Model.getSingleton().getOptionsParam().getConnectionParam(),
                                true,
                                HttpSender.MANUAL_REQUEST_INITIATOR);
                httpSender.sendAndReceive(msg2, true);

                if (msg2.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
                    // bail
                }

                if (msg2.getResponseHeader().isEmpty()) {
                    // bail
                }

                // Redirect to the un-minified resource
                HttpResponseHeader redirectHeader = new HttpResponseHeader("HTTP/1.1 307");
                redirectHeader.setHeader("location", libInfo.maxURI);
                msg.setResponseHeader(redirectHeader);
                msg.setResponseBody(new HttpResponseBody());
            }
        } catch (URIException e) {
        } catch (HttpMalformedHeaderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NullPointerException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return true;
    }
}
