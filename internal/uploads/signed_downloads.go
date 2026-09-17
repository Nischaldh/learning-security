package uploads

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"

	"time"
)

const signedDownloadTTL = 5 * time.Minute

func CreateSignedDownloadPath(signingKey [32]byte, fileID int64, now time.Time) string {
	expires := now.Unix() + int64(signedDownloadTTL.Seconds())
	signature := signDownload(signingKey, fileID, expires)
	return fmt.Sprintf("/files/%d/signed-download?expires=%d&signature=%s", fileID, expires, signature)
}

func VerifySignedDownload(signingKey [32]byte, fileId int64, expiresValue, signature string, now time.Time) bool {
	if expiresValue == "" || signature == "" {
		return false
	}

	expires, err := strconv.ParseInt(expiresValue, 10, 64)

	if err != nil || expires <= now.Unix() {
		return false
	}
	expectedSignature:= signDownload(signingKey, fileId, expires)
	providedBytes , err:=hex.DecodeString(signature)
	if err!=nil{
		return false
	}
	expectedBytes, err := hex.DecodeString(expectedSignature)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(providedBytes, expectedBytes) == 1
}

func signDownload(signingKey [32]byte, fileID, expires int64) string {
	mac := hmac.New(sha256.New, signingKey[:])
	fmt.Fprintf(mac, "GET\n/files/%d/signed-download\n%d", fileID, expires)
	signature := hex.EncodeToString(mac.Sum(nil))
	return signature
}
