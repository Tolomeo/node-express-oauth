const url = require('url');
const express = require("express")
const bodyParser = require("body-parser")
const axios = require("axios").default
const { randomString, timeout } = require("./utils")

const config = {
	port: 9000,

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
	tokenEndpoint: "http://localhost:9001/token",
	userInfoEndpoint: "http://localhost:9002/user-info",
}
let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/client")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/

app.get('/authorize', (req, res) => {
	state = randomString();

	res.redirect(url.format({
		pathname: config.authorizationEndpoint,
		query: {
			response_type: "code",
			client_id: config.clientId,
			redirect_uri : config.redirectUri,
			scope: "permission:name permission:date_of_birth",
			state
		}
	}));
})

app.get('/callback', async (req, res) => {
	const { state: callbackstate } = req.query

	if (callbackstate !== state) {
		return res.status(403).end();
	}

	const { data: { access_token } } = await axios({
		method: 'POST',
		url: config.tokenEndpoint,
		auth: {
			username: config.clientId,
			password: config.clientSecret
		},
		data: {
			code: req.query.code
		}
	});

	const { data } = await axios({
		method: 'GET',
		url: config.userInfoEndpoint,
		headers: {
			authorization: `bearer ${access_token}`,
		}
	});

	res.render("welcome", {
		user: data
	});
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = {
	app,
	server,
	getState() {
		return state
	},
	setState(s) {
		state = s
	},
}
