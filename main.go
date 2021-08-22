package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/pat"
	"github.com/urfave/negroni"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// 아래 컨피그를 통해서 oauth에 접근한다
var googleOauthConfig = oauth2.Config{
	RedirectURL: "http://localhost:3000/auth/google/callback",
	// os에 저장된 환경변수값을 가지고 온다
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_SECRET_KEY"),
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     google.Endpoint,
}

func googleLoginHandler(w http.ResponseWriter, r *http.Request) {
	// 유저에 브라우저에 temporary key를 심고 리디렉트가 왔을때 확인

	state := generateStateOauthCookie(w)
	// 어떤 URL로 보내줘야하는지 알려준다
	url := googleOauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	// 현재 시간부터 하루 뒤에 만료
	expiration := time.Now().Add(1 * 24 * time.Hour)

	b := make([]byte, 16) // 16byte
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b) // 랜덤하게 b를 채운다
	// 쿠키로 세팅
	cookie := &http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, cookie)
	return state
}

func googleAuthCallback(w http.ResponseWriter, r *http.Request) {
	// 쿠키를 먼저 읽어온다
	oauthstate, _ := r.Cookie("oauthstate")

	// 쿠키와 state 값을 비교, 다를 경우 우리가 요청한게 아니다
	if r.FormValue("state") != oauthstate.Value {
		log.Printf("invalid google oauth state cookie:%s state:%s\n", oauthstate.Value, r.FormValue("state"))
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// 구글에 요청해서 user info를 다시 가져온다
	data, err := getGoogleUserInfo(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	fmt.Fprint(w, string(data))
}

// user info request 하는 경로
const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

func getGoogleUserInfo(code string) ([]byte, error) {
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("Failed to Exchange %s\n", err.Error())
	}

	// AccessToken 을 붙여서 URL에 요청
	resp, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to Get UserInfo %s\n", err.Error())
	}

	return ioutil.ReadAll(resp.Body)
}

func main() {
	mux := pat.New()

	// 핸들러 생성, google에 로그인 요청
	mux.HandleFunc("/auth/google/login", googleLoginHandler)

	// 핸들러 생성,
	mux.HandleFunc("/auth/google/callback", googleAuthCallback)

	n := negroni.Classic()
	n.UseHandler(mux)
	http.ListenAndServe(":3000", n)
}
