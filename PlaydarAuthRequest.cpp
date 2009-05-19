/***************************************************************************
 *   Copyright 2009 Casey Link <unnamedrambler@gmail.com>                  *
 *   Copyright 2009 Last.fm Ltd.                                           *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.         *
 ***************************************************************************/

#include <QNetworkReply>
#include "PlaydarAuthRequest.h"
#include <QtNetwork/QNetworkAccessManager>
#include "JsonQt/lib/JsonToVariant.h"

PlaydarAuthRequest::PlaydarAuthRequest(QNetworkAccessManager* wam, PlaydarApi& api)
:m_wam(wam)
,m_api(api)
{
}

void 
PlaydarAuthRequest::start(QString applicationName)
{
    m_applicationName = applicationName;

    QNetworkReply* auth1Reply = m_wam->get( QNetworkRequest( m_api.auth1(applicationName) ) );
    if (auth1Reply) {
        connect(auth1Reply, SIGNAL(finished()), SLOT(onAuth1Finished()));
    } else {
        fail("couldn't issue auth_1 request");
    }
}

void 
PlaydarAuthRequest::onAuth1Finished()
{
    QNetworkReply *reply = (QNetworkReply*) sender();
    if (reply->error() == QNetworkReply::NoError)
    {
        using namespace std;

        QByteArray ba( reply->readAll() );
        QVariant data = JsonQt::JsonToVariant::parse( ba );
        if( data.type() != QVariant::Map )
            fail("bad json in auth1 response");
        QMap parsed = data.toMap();

        QVariant v = parsed["formtoken"];
        if( v.type() != QVariant::QString )
            fail("bad json in auth1 response");
        ParamList params;
        QUrl url = m_api.auth2( m_applicationName, v.toString(), params );

        // form encode:
        QByteArray form;
        typedef QPair<QString,QString> Param;
        foreach (Param p, params) {
            if (form.size()) {
                form += "&";
            }
            form += QUrl::toPercentEncoding( p.first ) + "="
                    + QUrl::toPercentEncoding( p.second );
        }
        QNetworkReply* auth2Reply = m_wam->post(QNetworkRequest(url), form);
        if (auth2Reply) {
            connect(auth2Reply, SIGNAL(finished()), SLOT(onAuth2Finished()));
            return;
        }
        fail("couldn't issue auth_2 request");
    }
}

void
PlaydarAuthRequest::onAuth2Finished()
{
    QNetworkReply *reply = (QNetworkReply*) sender();
    if (reply->error() == QNetworkReply::NoError) {
        using namespace std;

        QByteArray ba( reply->readAll() );
        QVariant data = JsonQt::JsonToVariant::parse( ba );
        if( data.type() != QVariant::Map )
            fail("");
        QMap parsed = data.toMap();

        QVariant v = parsed["authtoken"];
        if(v.type() != QString )
            fail("bad json in auth2 response");
        emit authed( v.toString() );
        return;
    }
    fail("");
}

void 
PlaydarAuthRequest::fail(const char*)
{
    emit error();
}
