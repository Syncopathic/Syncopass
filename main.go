package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	mr "math/rand" // Renamed to mr to not class with crypto/rand
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// The main struct for the password manager application that allows
// functions that are associated with it to access data that can
// be modified from any section of the program.
type Manager struct {
	Validated          chan bool
	LoggedIn           bool
	PassDir            string
	RootDir            string
	Exit               chan bool
	DecryptedPasswords map[string]string
	EncryptedPasswords map[string][]byte
	Loaded             bool
	mu                 sync.Mutex
}

// Small helper function for clearing the screen in Windows CMD prompt.
func clearScreen() {
	exec.Command("cmd", "/c", "cls")
}

// Uses a built-in bcrypt comparison method to compare the user's
// input to the stored hash.
func (m *Manager) validate(pass []byte) error {
	root, err := os.Open(m.RootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	rootHash := make([]byte, 60)
	_, err = root.Read(rootHash)
	if err != nil {
		return err
	}
	err = bcrypt.CompareHashAndPassword(rootHash, pass)
	if err != nil {
		return err
	}
	m.LoggedIn = true
	return nil
}

// Simple method for getting the user's root password and validating it.
func (m *Manager) login() ([]byte, error) {
	clearScreen()
	fmt.Print("\nEnter root password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}
	err = m.validate(password)
	if err != nil {
		return nil, err
	}
	return password, nil
}

// Only run if the application directory doesn't exist or if the root password
// folder cannot be found. Creates the new files, takes in a root password
// and stores the hash+salt to the file, which is created with read-only
// permissions.
func (m *Manager) firstTimeSetup() error {
	clearScreen()
	os.Mkdir("./SyncoPass", 0777)
	fmt.Print("Enter a root password: ")
	pass, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	err = os.WriteFile(m.RootDir, hash, 0600)
	if err != nil {
		return err
	}
	return nil
}

// Uses a SHA256 hash of the root password as a key for AES-GCM encryption
// of the password passed as an argument.
func (m *Manager) encryptPassword(pass []byte) ([]byte, error) {
	clearScreen()
	passwd, err := m.login()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(passwd)
	// Once password has been used, set to nil so as to not store it in memory
	passwd = nil
	key := h.Sum(nil)
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	encPass := gcm.Seal(nonce, nonce, pass, nil)
	return encPass, nil
}

// Scans through the passwords stored in a file, decrypts them and appends
// each to a pre-made map ready to be searched through, viewed, modified or deleted
func (m *Manager) decryptPasswords(pass []byte) {
	fi, err := os.Stat(m.PassDir)
	// Check to see if there are any passwords
	if err != nil {
		m.Loaded = true
		return
	}
	if fi.Size() <= 0 {
		m.Loaded = true
		return
	}
	// If passwords do exist, decrypt them
	h := sha256.New()
	h.Write(pass)
	key := h.Sum(nil)
	// Once password has been used, set to nil so as to not store it in memory
	pass = nil
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalln(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatalln(err)
	}
	f, err := os.Open(m.PassDir)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	if err != nil {
		log.Fatalln(err)
	}
	pairSep := []byte("######")
	passSep := []byte("++++++")
	allPs := make([]byte, 2048)
	_, err = f.Read(allPs)
	if err != nil {
		log.Fatalln(err)
	}
	pwuAll := bytes.Split(allPs, passSep)
	for _, row := range pwuAll {
		if len(row) <= 0 {
			break
		}
		pwu := bytes.Split(row, pairSep)
		if pwu[0][0] == 0 {
			break
		}
		if len(pwu[1]) < gcm.NonceSize() {
			log.Fatalln(err, pwu)
		}
		nonce, ctext := pwu[1][:gcm.NonceSize()], pwu[1][gcm.NonceSize():]
		pass, err := gcm.Open(nil, []byte(nonce), []byte(ctext), nil)
		if err != nil {
			log.Fatalln(err, pwu)
		}
		m.DecryptedPasswords[string(pwu[0])] = string(pass)
		m.EncryptedPasswords[string(pwu[0])] = pwu[1]
	}
	m.Loaded = true
}

// Iterates through the map of decrypted passwords and displays
// them in a formatted way to the screen.
func (m *Manager) viewPasswords() {
	clearScreen()
	if len(m.DecryptedPasswords) < 1 {
		fmt.Println("No passwords stored on disk!")
		return
	}
	for usage, pass := range m.DecryptedPasswords {
		fmt.Println(usage, "->", pass)
	}
}

// Takes the password for the passed usage argument and stores the usage
// with the encrypted password in the form of
// [usage]#[encrypted password]\n
func (m *Manager) writePassToFile(usage string, ep []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := os.OpenFile(m.PassDir, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	f.Write([]byte(usage))
	f.Write([]byte("######"))
	f.Write(ep)
	f.Write([]byte("++++++"))
	return nil
}

// Takes in a new usage and calls the writePassToFile function
// to append the encrypted password to the existing file.
func (m *Manager) newPassword() error {
	clearScreen()
	fmt.Print("What is the password for: ")
	reader := bufio.NewReader(os.Stdin)
	usage, err := reader.ReadString('\n')
	usage = strings.TrimSpace(usage)
	if err != nil {
		return err
	}
	fmt.Print("Enter password: ")
	pass, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	ep, err := m.encryptPassword(pass)
	if err != nil {
		return err
	}
	err = m.writePassToFile(usage, ep)
	if err != nil {
		return err
	}
	return nil
}

// Takes in a length specified by the user a prints a password
// that contains uppercase letters, lowercase letters, numbers, and symbols
// does not automatically use this password for anything since manual
// verification of randomness and security is recommended.
func (m *Manager) generatePassword() error {
	clearScreen()
	fmt.Print("Enter desired password length: ")
	lengthS, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	length, err := strconv.Atoi(strings.TrimSpace(lengthS))
	if err != nil {
		return err
	}
	if length < 10 {
		fmt.Println("WARNING: a generated password of length", length, "may be considered insecure")
	}
	r := mr.New(mr.NewSource(time.Now().Unix()))
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789" +
		"¬!£$%^&*(){}[]#~-=_+|/><.,';@:`?")
	var builder strings.Builder
	for i := 0; i < length; i++ {
		builder.WriteRune(chars[r.Intn(len(chars))])
	}
	fmt.Println("Generated password:", builder.String())
	return nil
}

// Takes user input of a password usage and takes in a new password.
// The password file is deleted and regenerated from the EncryptedPasswords
// map, which is a simple and efficient way to delete a password.
func (m *Manager) editPassword() error {
	m.viewPasswords()
	fmt.Print("Which password do you want to edit: ")
	i, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	i = strings.TrimSpace(i)
	pass := m.findPassword(i)
	if pass == nil {
		return errors.New("password not found")
	}
	log.Println("removing", i, "from password list...")
	delete(m.DecryptedPasswords, i)
	delete(m.EncryptedPasswords, i)
	log.Println("updating password file...")
	err = os.Remove(m.PassDir)
	if err != nil {
		log.Println(err)
	}
	for u, ep := range m.EncryptedPasswords {
		err = m.writePassToFile(u, ep)
		if err != nil {
			return err
		}
	}
	fmt.Print("Enter new password: ")
	newpass, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	ep, err := m.encryptPassword(newpass)
	if err != nil {
		return err
	}
	err = m.writePassToFile(i, ep)
	if err != nil {
		return err
	}
	return nil
}

// Searches through the decrypted passwords map to find if it exists
// and returns the password if it does.
func (m *Manager) findPassword(usage string) map[string]string {
	found := make(map[string]string)
	for u, p := range m.DecryptedPasswords {
		if strings.Contains(u, usage) {
			found[u] = p
		}
	}
	return found
}

// Displays the main menu for the password manager, containing 6 options
// for how the user can proceed.
func (m *Manager) displayMenu() error {
	clearScreen()
	fmt.Println("\n------ Menu ------\n1. View Passwords\n2. New Password\n3. Generate Password\n4. Edit Password\n5. Search for Password\n6. Exit")
	fmt.Print(">> ")
	i, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	i = strings.TrimSpace(i)
	if err != nil {
		return err
	}
	switch i {
	case "1":
		m.viewPasswords()
	case "2":
		err = m.newPassword()
		if err != nil {
			log.Println(err)
		}
	case "3":
		m.generatePassword()
	case "4":
		m.editPassword()
	case "5":
		fmt.Print("Enter the website to find the password: ")
		i, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return err
		}
		i = strings.TrimSpace(i)
		found := m.findPassword(i)
		if found == nil {
			log.Println("no passwords found for", i)
		}
		for u, pass := range found {
			fmt.Println(u, "->", pass)
		}
	case "6":
		os.Exit(0)
	default:
		log.Println("invalid input")
	}
	return nil
}

func main() {
	m := &Manager{
		LoggedIn:           false,
		Exit:               make(chan bool),
		PassDir:            "./SyncoPass/passwd.sp",
		RootDir:            "./SyncoPass/root.txt",
		EncryptedPasswords: make(map[string][]byte),
		DecryptedPasswords: make(map[string]string),
		Loaded:             false,
	}
	fmt.Println("Welcome to the totally awesome password manager CLI!!")
	// Check to see if a user already exists / first time running
	if _, err := os.Stat("./SyncoPass/root.txt"); err != nil {
		// If user doesn't exist, create new user, hash + salt + encrypt file with password
		err = m.firstTimeSetup()
		if err != nil {
			log.Println(err)
		}
	}
	// If user does exist, log in
	var passwd []byte = nil
	var err error
	for {
		if passwd, err = m.login(); err != nil {
			log.Println("error logging in")
			continue
		}
		break
	}
	log.Println("successful log in")
	// Once logged in, ask for option: view passwords, enter new password, generate new password, modify existing password, find password
	// While menu is being displayed and user is choosing decrypt passwords and store in array using channel to prevent race conditions
	for {
		//passwd = nil
		go m.decryptPasswords(passwd)
		err := m.displayMenu()
		if err != nil {
			log.Println(err)
		}
	}
}
