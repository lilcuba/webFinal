// Middleware function to check if user is authenticated
function authUser(req, res, next) {

    if (!req.user) {
        res.status(403);
        return res.send("You need to sign in.");
    }
    next();
}

function authRole(role) {
    return (req, res, next) => { 
        if (!req.user || req.user.role !== 'admin') {
            res.status(401);
            return res.send("Not allowed.");
        }
        next();
    };
}




module.exports = {
    authUser,
    authRole
};
