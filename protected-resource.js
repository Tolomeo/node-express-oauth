const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs")
const jwt = require('jsonwebtoken');
const { timeout } = require("./utils")

const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/

app.get('/user-info', (req, res) => {
	const { authorization } = req.headers;

	if (!authorization) {
		return res.status(401).end(); 
	}

	const token = authorization.slice(7);
	let tokenPayload;

	try {
		tokenPayload = jwt.verify(token, config.publicKey, { algorithms: ["RS256"] });
	} catch (error) {
		return res.status(401).end();	
	}

	const { userName, scope } = tokenPayload;

	const response = scope.split(' ').reduce((responseObj, permission) => {
		const permissionKey = permission.slice(11);
		responseObj[permissionKey] = users[userName][permissionKey];
		return responseObj;
	}, {})

	res.json(response);
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes
module.exports = {
	app,
	server,
}
