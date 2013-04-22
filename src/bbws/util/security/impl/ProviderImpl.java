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
import bbws.util.security.oauth.OAuth;
import bbws.util.security.oauth.impl.ServerImpl;
import bbws.util.security.DefaultProvider;

public class ProviderImpl extends DefaultProvider
{
    public ProviderImpl(long requestTimeout,String baseuri,String authHeader,String consumer_secret)
    {
        this.requestTimeout = requestTimeout; //seconds
        this.oauthParams = getOAuthParams(authHeader);
        this.server = new ServerImpl(baseuri,this.oauthParams.get(OAuth.consumer_key_url_key),consumer_secret);
    }
}
