const fs = require("fs")
const url = require("url");
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/

app.get('/authorize', (req, res) => {
	const { query } = req;
	const { client_id } = query;
	const client = clients[client_id];

	if (!client) {
		return res.status(401).end();	
	}

	let { scope } = query;
	scope = scope.split(" ");
	const validScope = containsAll(client.scopes, scope);

	if (!validScope) {
		return res.status(401).end();	
	}

	const requestId = randomString();
	requests[requestId] = query;

	res.render("login", {
		client,
		scope: query.scope,
		requestId
	});
});

app.post('/approve', (req, res) => {
	const { userName, password, requestId } = req.body;

	if (users[userName] !== password) {
		res.status(401).end();
	}

	const request = requests[requestId];
	delete requests[requestId];

	if (!request) {
		return res.status(401).end();
	}

	const authorizationCode = randomString();
	const authorization = {
		clientReq: request,
		userName
	};

	authorizationCodes[authorizationCode] = authorization;

	const { redirect_uri, state } = request;

	res.redirect(url.format({
		pathname: redirect_uri, 
		query: {
			code: authorizationCode,
			state
		}
	}))
})

app.post('/token', (req, res) => {
	const { authorization } = req.headers;

	if (!authorization) {
		return res.status(401).end();
	}

	const { clientId, clientSecret } = decodeAuthCredentials(authorization);
	const client = clients[clientId];

	if (!client || client.clientSecret !== clientSecret) {
		return res.status(401).end();
	}

	const { code } = req.body;
	const authorizationData = authorizationCodes[code];

	if (!authorizationData) {
		return res.status(401).end();
	}

	delete authorizationCodes[code];

	const { userName, clientReq: { scope } } = authorizationData;
	const access_token = jwt.sign({ userName, scope }, config.privateKey, { algorithm: 'RS256'});

	res.json({
		access_token,
		token_type: "Bearer"
	});
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
