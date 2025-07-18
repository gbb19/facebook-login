package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

// loadConfig reads the OAuth values from environment variables and
// returns an *oauth2.Config.  The program exits if any required value
// is missing because continuing without them makes no sense.
func loadConfig() *oauth2.Config {
	_ = godotenv.Load()
	appID := os.Getenv("FACEBOOK_APP_ID")
	appSecret := os.Getenv("FACEBOOK_APP_SECRET")
	redirect := os.Getenv("FACEBOOK_REDIRECT_URI")
	if appID == "" || appSecret == "" || redirect == "" {
		log.Fatal("FACEBOOK_APP_ID, _SECRET, and _REDIRECT_URI must be set in .env or the host environment")
	}

	return &oauth2.Config{
		ClientID:     appID,
		ClientSecret: appSecret,
		RedirectURL:  redirect,
		Scopes: []string{
			"public_profile",
			"pages_show_list",
			"pages_manage_metadata",
			"pages_read_engagement",
			"pages_manage_posts",
			"pages_read_user_content",
		},
		Endpoint: facebook.Endpoint,
	}
}

var oauthConf = loadConfig()

// randomState returns a base64‑encoded 128‑bit random string for CSRF
// protection during OAuth.
func randomState() string {
	b := make([]byte, 16) // 128 bits
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("rand failed: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Page represents one Facebook Page (subset of fields).
// access_token is only present if the user granted the app access to
// that Page in the permissions dialog.
type Page struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	AccessToken string `json:"access_token,omitempty"`
}

type accountsResp struct {
	Data []Page `json:"data"`
}

// fetchPages returns all Pages the user administers, including access
// tokens for the Pages the user selected in the permissions dialog.
func fetchPages(userToken string) ([]Page, error) {
	url := fmt.Sprintf("https://graph.facebook.com/v23.0/me/accounts?fields=id,name,access_token&access_token=%s", userToken)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("graph api status %d", resp.StatusCode)
	}

	var ar accountsResp
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return nil, err
	}
	return ar.Data, nil
}

// subscribePage subscribes the calling App to the given Page so Graph
// API Webhooks for that Page (comments, messages, etc.) are delivered
// to the App's callback URL registered in the App Dashboard.
func subscribePage(pageID, pageToken string) error {
	url := fmt.Sprintf("https://graph.facebook.com/v23.0/%s/subscribed_apps", pageID)
	body := strings.NewReader("subscribed_fields=feed,messages")

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	q := req.URL.Query()
	q.Set("access_token", pageToken)
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("subscribe failed status %d", resp.StatusCode)
	}
	return nil
}

// State management in file
const stateFile = "states.json"

type stateStore struct {
	States []string `json:"states"`
}

// saveStateToFile appends a state to the states.json file
func saveStateToFile(state string) error {
	var store stateStore
	f, err := os.OpenFile(stateFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	if len(b) > 0 {
		_ = json.Unmarshal(b, &store)
	}
	store.States = append(store.States, state)
	f.Seek(0, 0)
	f.Truncate(0)
	return json.NewEncoder(f).Encode(store)
}

// checkAndDeleteStateInFile checks if state exists, deletes it, and returns true if found
func checkAndDeleteStateInFile(state string) (bool, error) {
	var store stateStore
	f, err := os.OpenFile(stateFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return false, err
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	if len(b) > 0 {
		_ = json.Unmarshal(b, &store)
	}
	found := false
	newStates := make([]string, 0, len(store.States))
	for _, s := range store.States {
		if s == state && !found {
			found = true
			continue
		}
		newStates = append(newStates, s)
	}
	store.States = newStates
	f.Seek(0, 0)
	f.Truncate(0)
	_ = json.NewEncoder(f).Encode(store)
	return found, nil
}

// GET /auth/facebook/url - returns Facebook login URL
func facebookURLHandler(w http.ResponseWriter, r *http.Request) {
	state := randomState()
	if err := saveStateToFile(state); err != nil {
		http.Error(w, "failed to save state", http.StatusInternalServerError)
		return
	}
	url := oauthConf.AuthCodeURL(state, oauth2.AccessTypeOffline)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"url": url, "state": state})
}

// POST /auth/facebook/callback - receives code+state from frontend
func facebookCallbackHandler(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	var body reqBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.Code == "" || body.State == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}
	// check state in file
	found, err := checkAndDeleteStateInFile(body.State)
	if err != nil {
		http.Error(w, "state check error", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}
	// exchange code → user token
	token, err := oauthConf.Exchange(context.Background(), body.Code)
	if err != nil {
		http.Error(w, fmt.Sprintf("token exchange failed: %v", err), http.StatusBadRequest)
		return
	}
	// fetch the user's Pages with page access tokens
	pages, err := fetchPages(token.AccessToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("fetch pages failed: %v", err), http.StatusBadRequest)
		return
	}
	// Subscribe ทุก Page ที่มี access_token
	for _, page := range pages {
		if page.AccessToken == "" {
			continue
		}
		if err := subscribePage(page.ID, page.AccessToken); err != nil {
			http.Error(w, fmt.Sprintf("subscribe page %s failed: %v", page.ID, err), http.StatusBadRequest)
			return
		}
	}
	// บันทึก pages ลงไฟล์ (optionally per user)
	f, err := os.Create("pages.json")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create file: %v", err), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(pages); err != nil {
		http.Error(w, fmt.Sprintf("failed to write file: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/facebook/url", facebookURLHandler)           // step 1
	mux.HandleFunc("/auth/facebook/callback", facebookCallbackHandler) // step 4
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
