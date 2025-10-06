/**
 * Enum representing where OTP data should be saved: Redis or MongoDB.
 */
var saveIn;
(function (saveIn) {
    /**
     * Store OTP in Redis.
     */
    saveIn["REDIS"] = "redis";
    /**
     * Store OTP in MongoDB.
     */
    saveIn["DB"] = "DB";
})(saveIn || (saveIn = {}));
export { saveIn };
