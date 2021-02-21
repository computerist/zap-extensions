package org.zaproxy.zap.extension.maxify;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.view.ZapMenuItem;

class LibInfo {
	String filename;
	String minSha256Digest;
	String maxSha256Digest;
	String minURI;
	String maxURI;
}

public class ExtensionMaxifier extends ExtensionAdaptor implements ProxyListener {
	private static final String NAME = "Maxify";
	private static final String PREFIX = "maxify";
	
	private ZapMenuItem menuMaxifier;
	
	private Map<String, LibInfo> libsByFilename;

    public ExtensionMaxifier() {
        super(NAME);
        setI18nPrefix(PREFIX);
        
        this.libsByFilename = new HashMap<String, LibInfo>();
        LibInfo jquery224 = new LibInfo();
        jquery224.filename = "jquery-2.2.4.min.js";
        jquery224.minURI = "https://code.jquery.com/jquery-2.2.4.min.js";
        jquery224.minSha256Digest = "BbhdlvQf/xTY9gja0Dq3HiwQF8LaCRTXxZKRutelT44=";
        jquery224.maxURI = "https://code.jquery.com/jquery-2.2.4.js";
        jquery224.maxSha256Digest = "iT6Q9iMJYuQiMWNd9lDyBUStIq/8PuOW33aOqmvFpqI=";
        this.libsByFilename.put(jquery224.filename, jquery224);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        //this.api = new MaxifierAPI(this);
        //extensionHook.addApiImplementor(this.api);

        // As long as we're not running as a daemon
        if (getView() != null) {
        	extensionHook.getProxyListenerList().add(this);
            //extensionHook.getHookMenu().addToolsMenuItem(getMenuMaxifier());
            //extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgMenuExample());
            //extensionHook.getHookView().addStatusPanel(getStatusPanel());
        }
    }

    private ZapMenuItem getMenuMaxifier() {
        if (menuMaxifier == null) {
        	menuMaxifier = new ZapMenuItem(PREFIX + ".topmenu.tools.title");

        	menuMaxifier.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent ae) {
                            // This is where you do what you want to do.
                            // In this case we'll just show a popup message.
                            View.getSingleton()
                                    .showMessageDialog(
                                            Constant.messages.getString(
                                                    PREFIX + ".topmenu.tools.msg"));
                            // And display a file included with the add-on in the Output tab
                            //displayFile(EXAMPLE_FILE);
                        }
                    });
        }
        return menuMaxifier;
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
			System.out.println("Inspecting... " + requestURI);
			String path = requestURI.getPath();
			int sepPos = path.lastIndexOf('/');
			String filename = sepPos >= 0 ? path.substring(sepPos + 1): path;
			System.out.println("Filename is " + filename);
			if (this.libsByFilename.containsKey(filename)) {
				System.out.println("filename matches!");
				LibInfo libInfo = this.libsByFilename.get(filename);
				String digestString = DigestUtils.sha256Hex(body.getBytes());
				
				// We can compare the served version with the expected digest of the minified script
				if (digestString.equals(libInfo.minSha256Digest)) {
					System.out.println("Minified script digests do not match:");
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

	            if (msg.getResponseHeader().isEmpty()) {
	                //bail
	            }
	            msg.setResponseHeader(msg2.getResponseHeader());
	            msg.setResponseBody(msg2.getResponseBody());
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
