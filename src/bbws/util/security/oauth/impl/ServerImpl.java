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
import bbws.util.security.oauth.Server;
import bbws.util.security.oauth.DefaultOAuth;

//java
import java.util.Calendar;

public class ServerImpl extends DefaultOAuth implements Server
{
    public ServerImpl(String baseuri,String consumer_key,String consumer_secret)
    {
        if(!baseuri.endsWith("/")){this.baseuri = baseuri+"/";}
        else{this.baseuri = baseuri;}
        this.consumer_key = consumer_key;
        this.consumer_secret = consumer_secret;
    }

    @Override
    public boolean isRequestValid(long requestTimeout,String requestMethod,String resource,String nonce,String signature,long timestamp)
    {
        //check nonce
        //nonceHasBeenUsedRecently(nonce,requestTimeout);
        //check timestamp occured before timeout or after current time, reject request if true
        long currentTimestamp = Calendar.getInstance().getTimeInMillis()/1000;
        if(timestamp<(Calendar.getInstance().getTimeInMillis()/1000-requestTimeout)||timestamp>currentTimestamp)
        {
            return false;
        }

        //check signature
        try
        {
            return isSignatureValid(requestMethod,this.baseuri+resource,this.consumer_key,this.consumer_secret,nonce,Long.toString(timestamp),signature);
        }
        catch(Exception e)
        {
            System.out.println("Error checking signature: "+e.getMessage());
        }
        return false;
    }
}
