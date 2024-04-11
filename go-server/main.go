// package main
//
// import (
// 	"bufio"
// 	"bytes"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"log/slog"
// 	"net/http"
// 	"time"
//
// 	"github.com/gin-gonic/gin"
// )
//
// // https://docker-test.fly.dev/api/chat
//
// // Message represents the nested message object in the JSON response
// type Message struct {
// 	Role    string `json:"role"`
// 	Content string `json:"content"`
// }
//
// // Response represents the entire JSON response
// type Response struct {
// 	Model     string    `json:"model"`
// 	CreatedAt time.Time `json:"created_at"`
// 	Message   Message   `json:"message"`
// 	Done      bool      `json:"done"`
// }
//
// type RequestBody struct {
// 	Model   string  `json:"model"`
// 	Message Message `json:"message"`
// }
//
// func main() {
// 	r := gin.Default()
// 	r.GET("/ping", func(c *gin.Context) {
// 		slog.Info("making request to go server two... ")
//
// 		// Do the same thing to internal LLM Server here
// 		res, err := http.Get("http://go-server-two.internal:8080/ping")
// 		if err != nil {
//
// 			c.JSON(http.StatusOK, gin.H{
// 				"message": "error",
// 			})
// 			slog.Error("error line 22")
//
// 		}
//
// 		body, err := io.ReadAll(res.Body)
// 		res.Body.Close()
// 		if res.StatusCode > 299 {
// 			c.JSON(http.StatusOK, gin.H{
// 				"message": "statuscode weird",
// 			})
// 			slog.Error("Response failed with status code: %d and\nbody: %s\n", res.StatusCode, body)
// 		}
// 		if err != nil {
//
// 			c.JSON(http.StatusOK, gin.H{
// 				"message": "error at line 31",
// 			})
// 			slog.Error("Error at line 31 of code")
// 		}
// 		fmt.Printf("%s", body)
//
// 		c.JSON(http.StatusOK, gin.H{
// 			"message": "pong",
// 		})
// 	})
//
// 	// make post request to https://docker-test.fly.dev/api/chat
// 	//   {
// 	//   "model": "mistral",
// 	//   "messages": [
// 	//     { "role": "user", "content": "tell me a joke for today" }
// 	//   ]
// 	// }
//
// 	// Parse the reponse
// 	// Unmarshal JSON data into a Response struct
// 	r.GET("/", func(c *gin.Context) {
// 		// message := ""
// 		// Prepare the request body
// 		requestBody := RequestBody{
// 			Model: "mistral",
// 			Message: Message{
// 				Role:    "user",
// 				Content: "tell me a funny joke that I will remember for the rest of my life",
// 			},
// 		}
//
// 		// Convert the request body to JSON
// 		requestBodyBytes, err := json.Marshal(requestBody)
// 		if err != nil {
// 			fmt.Println("Error marshalling JSON:", err)
// 			return
// 		}
//
// 		resp, err := http.Post("https://docker-test.fly.dev/api/chat", "application/json", bytes.NewBuffer(requestBodyBytes))
// 		if err != nil {
// 			fmt.Println("Error making POST request:", err)
// 			return
// 		}
// 		defer resp.Body.Close()
//
// 		// Check the response status
// 		if resp.StatusCode != http.StatusOK {
// 			fmt.Println("Error: Unexpected response status code:", resp.StatusCode)
// 			return
// 		}
//
// 		// haha, err := io.ReadAll(resp.Body)
// 		// if err != nil {
// 		// 	panic(err)
// 		// }
// 		// lines := bytes.Split(haha, []byte("\n"))
//   //   fmt.Println("Lines: ", len(lines))
// 		//
// 		// for _, line := range lines {
// 		// 	// Create a new Response struct to hold the parsed data
// 		// 	var response map[string]interface{}
// 		//
// 		// 	// Unmarshal the JSON into the Response struct
// 		// 	err := json.Unmarshal(line, &response)
// 		// 	if err != nil {
// 		// 		fmt.Println("Error unmarshalling JSON:", err)
// 		// 		continue
// 		// 	}
// 		//
// 		// 	fmt.Println("Response: ", response)
// 		// }
// 		// Create a new scanner to read the response body line by line
// 		scanner := bufio.NewScanner(resp.Body)
// 		// scanner.Split(bufio.ScanLines)
// 		//   fmt.Println("scanner.text: ", scanner.Text())
//
// 		str := ""
//
// 		// Iterate over each line
// 		for scanner.Scan() {
// 			fmt.Println("I looped")
// 			// Extract the JSON string from the line
// 			jsonString := scanner.Bytes()
// 			fmt.Println("jsonString: ", jsonString)
// 			str = str + string(jsonString)
//
// 			// Decode the JSON string into a Response struct
// 			var response map[string]interface{}
// 			err := json.Unmarshal(jsonString, &response)
// 			if err != nil {
// 				fmt.Println("Error decoding JSON:", err)
// 				continue
// 			}
//
// 			// Print the content from each response
// 			fmt.Println("Content:", response)
//
// 			// c.JSON(http.StatusOK, gin.H{
// 			// 	"message": response,
// 			// })
//
// 		}
//
// 		c.JSON(http.StatusOK, gin.H{
// 			"message": str,
// 		})
//
// 		// Check for any scanning errors
// 		// if err := scanner.Err(); err != nil {
// 		// 	fmt.Println("Error scanning:", err)
// 		// }
// 		// Read the response body
// 		// var responseData map[string]interface{}
// 		// if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
// 		// 	fmt.Println("Error decoding response JSON:", err)
// 		// 	return
// 		// }
// 		//
// 		// // Print the response data
// 		// fmt.Println("Response Data:", responseData)
//
// 	})
// 	// var response Response
//
// 	r.Run() // listen and serve on 0.0.0.0:8080
// }

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"log"
	"log/slog"
	"net/http"
	"time"
)

type ChatResponse struct {
	Model     string  `json:"model"`
	CreatedAt string  `json:"created_at"`
	Message   Message `json:"message"`
	Done      bool    `json:"done"`
	Metrics
}

type Metrics struct {
	TotalDuration      time.Duration `json:"total_duration,omitempty"`
	LoadDuration       time.Duration `json:"load_duration,omitempty"`
	PromptEvalCount    int           `json:"prompt_eval_count,omitempty"`
	PromptEvalDuration time.Duration `json:"prompt_eval_duration,omitempty"`
	EvalCount          int           `json:"eval_count,omitempty"`
	EvalDuration       time.Duration `json:"eval_duration,omitempty"`
}

type ChatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type Message struct {
	Role    string `json:"role"` // one of ["system", "user", "assistant"]
	Content string `json:"content"`
}

func GetOllamaStreamResponses(ch chan<- string, prompt string) {
	// Create empty content for LLM response
	content := ""
	// Log info about the prompt
	slog.Info("Received prompt", "prompt", prompt)

	// Prepare payload
	payload := ChatRequest{
		Model: "mistral",
		Messages: []Message{
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	// Marshal the payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		slog.Error("Error marshaling JSON payload:", err)
		return
	}

	// Make a POST request with the JSON payload
	resp, err := http.Post("https://docker-test.fly.dev/api/chat", "application/json", bytes.NewBuffer(jsonPayload))
	// Replace with https://docker-test.internal:8080/api/chat later
	if err != nil {
		fmt.Println("Error making POST request:", err)
		return
	}
	defer resp.Body.Close()

	// Check if the response status code is not in the 2xx range
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slog.Error("Received non-successful response:", "statuscode", resp.StatusCode)
		return
	}

	// Create a new scanner to read the response body
	scanner := bufio.NewScanner(resp.Body)

	// Iterate over each line in the response body
	for scanner.Scan() {
		// Process each line of the response
		line := scanner.Bytes() // Use Bytes() instead of Text() for []byte

		var response ChatResponse

		err := json.Unmarshal(line, &response)
		if err != nil {
			fmt.Println("Error unmarshalling JSON:", err)
			continue
		}

		content = content + response.Message.Content
	}

	// Check if any errors occurred during scanning
	if err := scanner.Err(); err != nil {
		slog.Error("Error reading response body:", err)
		return
	}

	ch <- content
}

// Create new type Middleware function: take http.HandlerFunc as argument and return new http.HandlerFunc
type Middleware func(http.HandlerFunc) http.HandlerFunc

func AuthenticationMiddleware() Middleware {
	return func(f http.HandlerFunc) http.HandlerFunc {

		return func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Checking if request has valid signature...")

			signature := r.Header.Get("LoveLoomAI-Signature")
			message := r.Header.Get("LoveLoomAI-Message")
			public_key := r.Header.Get("LoveLoomAI-Publickey")

			public_key_bytes, _ := base64.StdEncoding.DecodeString(public_key)

			pub, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("public_key", string(pub))

			if signature == "" || message == "" || public_key == "" {
				http.Error(w, "Bad Request: Missing required headers: LoveLoomAI-Signature, LoveLoomAI-Message, LoveLoomAI-Publickey", http.StatusBadRequest)
				return
			}

			if len([]byte(public_key_bytes)) != 32 {
				http.Error(w, "Bad Request: LoveLoomAI-Publickey has bad public key length", http.StatusBadRequest)
				return

			}

			if isValid := VerifySignature(public_key_bytes, signature, message); !isValid {
				slog.Error("Unauthorized Request")
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
		}
	}
}

func VerifySignature(public_key ed25519.PublicKey, signature string, message string) bool {

	isValid := ed25519.Verify([]byte(public_key), []byte(message), []byte(signature))

	return isValid
}

func Logging() Middleware {

	// Create a new Middleware
	return func(f http.HandlerFunc) http.HandlerFunc {

		// Define the http.HandlerFunc
		return func(w http.ResponseWriter, r *http.Request) {

			// Do middleware things
			slog.Info("logging info to terminal", "method", r.Method, "path", r.URL.Path)

			// Call the next middleware or handler
			f(w, r)
			slog.Info("logging info to terminal again", "method", r.Method, "path", r.URL.Path)

		}
	}
}

// Method ensures that url can only be requested with a specific method, else returns a 400 Bad Request
func Method(m string) Middleware {

	// Create a new Middleware
	return func(f http.HandlerFunc) http.HandlerFunc {

		// Define the http.HandlerFunc
		return func(w http.ResponseWriter, r *http.Request) {

			// Do middleware things
			if r.Method != m {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			// Call the next middleware/handler in chain
			f(w, r)
		}
	}
}

// Chain applies middlewares to a http.HandlerFunc
func Chain(f http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
	for _, m := range middlewares {
		f = m(f)
	}
	return f
}

func main() {

	// Define the JSON payload

	// Create a new ServeMux instance
	mux := http.NewServeMux()

	// Register handler functions for different routes
	mux.HandleFunc("/api/chat", Chain(ChatHandler, Method("POST"), Logging()))
	mux.HandleFunc("/hello", Chain(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("HELLOOOO"))
	}, AuthenticationMiddleware(), Method("POST")))

	// Create an HTTP server using the mux
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Start the server
	slog.Info("Server listening on port 8080...")
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}

type OllamaPrompt struct {
	Prompt string `json:"prompt"`
}

func ChatHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure request body is closed when done
	defer r.Body.Close()
	// Start a new goroutine to handle the request

	var ollamaPrompt OllamaPrompt
	// Recomend not to use io.ReadAll
	// requestBodyBytes, err := io.ReadAll(r.Body)
	err := json.NewDecoder(r.Body).Decode(&ollamaPrompt)

	if err != nil {
		slog.Info("error while reading request body", "method", r.Method, "url", r.URL.Path)
	}

	messages := make(chan string)

	go GetOllamaStreamResponses(messages, ollamaPrompt.Prompt)

	str := <- messages

	slog.Info("Received chat response ", "chat_response", str)
	w.Header().Set("Content-Type", "application/json")

	// Set the status code to 200 OK
	w.WriteHeader(http.StatusOK)

	responseJSON, err := json.Marshal(map[string]interface{}{"message": str})
	if err != nil {
		http.Error(w, "Failed to marshal JSON response", http.StatusInternalServerError)
		return
	}
	w.Write(responseJSON)

}
