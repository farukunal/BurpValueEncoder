package burp;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IHttpListener {

	private IExtensionHelpers helpers;
	PrintWriter stdout;
	private String[] encName = {"base64", "url", "asciiHex"};
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.setExtensionName("Value Encoder");

		stdout = new PrintWriter(callbacks.getStdout(), true);

		stdout.println("\r\nValue Encoder ver 1.0 installed successsfully");
		stdout.println("Using:");
		stdout.println("\r\n\t_base64'Your Value'_base64");
		stdout.println("\t_url'Your Value'_url");
		stdout.println("\t_asciiHex'Your Value'_asciiHex");
		stdout.println("\r\nCopyright © 2016 BiznetLab by Faruk UNAL");
		stdout.println("_____________________________________________\r\n\r\n\r\n\r\n");

		helpers = callbacks.getHelpers();
		callbacks.registerHttpListener(this);
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (messageIsRequest) {
			try {
				IHttpService httpService = messageInfo.getHttpService();

				IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
				List headers = reqInfo.getHeaders(); 
				String request = new String(messageInfo.getRequest());
				String messageBody = request.substring(reqInfo.getBodyOffset());
				String mydata = messageBody;
				Pattern pattern;
				Matcher matcher;

				for (int i = 0; i < encName.length; i++) {
					if (messageBody.contains("_"+encName[i]+"'")) {
						try {
							mydata = messageBody;
							pattern = Pattern.compile("_"+encName[i]+"'(.*?)'_"+encName[i]+"");
							matcher = pattern.matcher(mydata);
							while (matcher.find()) {
								mydata = mydata.replace("_"+encName[i]+"'" + matcher.group(1) + "'_"+encName[i]+"",
										encodeFK(matcher.group(1),encName[i]));
							}
							messageBody = mydata;
						} catch (Exception e) {
							stdout.println("Exception: encoding:"+encName[i]+"    Exc:"+ e.getLocalizedMessage().toString());
						}
					}
				}  
				byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
				messageInfo.setRequest(updateMessage);

			} catch (Exception e) {
				stdout.println("Exception: " + e.getLocalizedMessage().toString());
			}
		}
	}

	private String encodeFK(String textFK,String enc)
	{
		try {
			if(enc.equalsIgnoreCase("base64"))
			{
				byte[] authBytes = textFK.getBytes(StandardCharsets.UTF_8);
				return	Base64.getEncoder().encodeToString(authBytes);
			}
			else if(enc.equalsIgnoreCase("url"))
			{
				return URLEncoder.encode(textFK, "UTF-8");
			}else if(enc.equalsIgnoreCase("asciiHex"))
			{
				return String.format("%04x", new BigInteger(1, textFK.getBytes()));
			}
		} catch (Exception e) { 
		}
		return textFK;
	}
}
