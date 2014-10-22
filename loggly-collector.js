var crypto = require('crypto');
var http = require('http');
var loggly = require('loggly');
var dotenv = require('dotenv');

dotenv.load();

var logglyClient = loggly.createClient({
	token: process.env.LOGGLY_TOKEN,
	subdomain: process.env.LOGGLY_SUBDOMAIN,
	tags: [],
	json: true,
	useTagHeader: false
});

var parseSignedRequest = function(signedRequest, key) {
	if (!signedRequest) {
		throw 'Missing signed request';
	}
	if (!key) {
		throw 'Missing signing key';
	}
	var requestParts = signedRequest.split('.');
	if (requestParts.length !== 2) {
		throw 'Malformed signed request';
	}
	var signature = requestParts[0];
	var payload = requestParts[1];
	if (!payload) {
		throw 'Missing request signature';
	}
	if (!payload) {
		throw 'Missing request payload';
	}
	var valid = crypto.createHmac('sha256', key).update(payload).digest('base64');
	if (!valid) {
		throw 'Invalid signature';
	}

	return {
		signature: signature,
		payload: JSON.parse((new Buffer(payload, 'base64')).toString())
	};
}

var port = process.env.PORT || 1080;
var hostname = process.env.HOSTNAME || '127.0.0.1';
var headers = {
	"Content-Type": "application/json",
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Max-Age": "3628800",
	"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
	"Access-Control-Allow-Headers": "Accept, Authorization, Content-Type"
};
var oneDay = 1000 * 60 * 60 * 24;
var server = http.createServer(function (request, response) {
	if (request.method !== 'POST') {
		response.writeHead(200, headers);
		response.end();
	}
	var content = '';
	request.on('data', function(chunk) {
		content += chunk;
	});
	request.on('end', function() {
		try {
			var signedRequest = (request.headers.authorization || '').split(' ').slice(-1)[0];
			var parsedSignedRequest = parseSignedRequest(signedRequest, process.env.CONSUMER_SECRET);
			var context = parsedSignedRequest.payload.context;
			var events = JSON.parse(content).map(function(event) {
				var eventTime = new Date(event.time).getTime();
				var now = new Date().getTime();
				event.time = (new Date(eventTime)).toISOString();
				event.sendTime = (new Date(now)).toISOString();
				if ((now - eventTime) >= oneDay) {
					// Loggly can't accept event times more than a day old, so log an event time of midnight UTC
					event.eventTime = event.sendTime.split('T')[0] + 'T00:00:00.000Z';
					event.delayed = true;
				} else {
					event.eventTime = event.time;
				}
				event.data.user = {
					email: context.user.email,
					roleId: context.user.roleId,
					username: context.user.userName,
					userId: context.user.userId,
					orgName: context.organization.name,
					orgId: context.organization.organizationId,
					ip: request.headers['x-forwarded-for'] || request.connection.remoteAddress
				};
				return event;
			});
			if (events.length > 0) {
				logglyClient.log(events, [events[0].data.user.orgId], function(error, result) {
					if (error) {
						throw error;
					}
					console.log('Logged ' + events.length + ' event' + (events.length > 1 ? 's' : '') + ' to loggly', result);
					response.writeHead(200, headers);
					response.end("{}");
				});
			} else {
				console.log('No events to log');
				response.writeHead(200, headers);
				response.end("{}");
			}
		} catch(error) {
			response.writeHead(400, headers);
			response.end(JSON.stringify({ error: error.toString() }));
			return;
		}
	});
}).listen(port, hostname);
console.log('Server running at ' + hostname + ':' + port);
