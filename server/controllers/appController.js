/** POST: http://localhost:8080/api/register
    @param : {
        "username" : "example123",
        "password" : "example123",
        "email" : "test@gmail.com",
        "firstName" : "bill",
        "lastName" : "william",
        "mobile" : 8088983809,
        "address" : "Apt. 556, kulas Light, Gwenborough",
        "profile" : ""
    }
 */

export async function register(req, res){
    res.json('register route');
}

export async function login(req, res){
    res.json('login route');
}

export async function getUser(req, res){
    res.json('getUser route');
}

export async function updateUser(req, res){
    res.json('updateUser route');
}

export async function generateOTP(req, res){
    res.json('generateOTP route');
}

export async function verifyOTP(req, res){
    res.json('verifyOTP route');
}

export async function createResetSession(req, res){
    res.json('createResetSession route');
}

export async function resetPassword(req, res){
    res.json('resetPassword route');
}
