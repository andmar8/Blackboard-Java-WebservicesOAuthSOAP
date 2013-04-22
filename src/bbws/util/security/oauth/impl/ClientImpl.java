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
package bbws.util.security.oauth.impl;

//bbws
import bbws.util.security.oauth.Client;
import bbws.util.security.oauth.DefaultOAuth;

//java
import java.net.URL;

public class ClientImpl extends DefaultOAuth implements Client
{
    public ClientImpl(String baseuri,String consumer_key,String consumer_secret)
    {
        if(!baseuri.endsWith("/")){this.baseuri = baseuri+"/";}
        else{this.baseuri = baseuri;}
        this.consumer_key = consumer_key;
        this.consumer_secret = consumer_secret;
    }

    @Override
    public String getOAuthHeaderWithSignature(String method,String resource)
    {
        if(resource==null){resource="";}
        try
        {
            return "OAuth realm=\""+new URL(this.baseuri).getPath()+resource+"\","+getOAuthHeadersWithSignature(method,this.baseuri,resource,this.consumer_key,this.consumer_secret,java.util.UUID.randomUUID().toString(),""+java.util.Calendar.getInstance().getTimeInMillis()/1000);
        }
        catch(Exception e)
        {
            System.out.println(e.getMessage());
            return "";
        }
    }
}
