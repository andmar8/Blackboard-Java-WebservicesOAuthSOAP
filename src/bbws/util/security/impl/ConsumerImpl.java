/*
    Blackboard Webservices OAuth SOAP Implementation
    Copyright (C) 2011-2013 Andrew Martin, Newcastle University

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package bbws.util.security.impl;

//bbws
import bbws.util.security.Consumer;
import bbws.util.security.DefaultConsumer;
import bbws.util.security.oauth.impl.ClientImpl;

//sun
import com.sun.xml.ws.developer.WSBindingProvider;
import com.sun.xml.ws.api.message.Headers;

import javax.xml.namespace.QName;

public class ConsumerImpl extends DefaultConsumer implements Consumer
{
    public ConsumerImpl(String baseuri,String consumer_key,String consumer_secret)
    {
        this.oauth = new ClientImpl(baseuri,consumer_key,consumer_secret);
    }

    @Override
    public void doAuth(WSBindingProvider client, String requestMethod, String resource)
    {
        client.setOutboundHeaders(Headers.create(new QName("Authorization"),oauth.getOAuthHeaderWithSignature(requestMethod,resource)));
    }
}
