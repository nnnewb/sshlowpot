// sshlowpot is a low-interaction ssh honeypot
package main

// sshlowpot.go
// Low-interaction honeypot
// By J. Stuart McMurray
// Created 20160119
// Last Modified 20160119

// Modified by weak_ptr <weak_ptr@outlook.com>

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"time"

	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
)

type CliArgument struct {
	VerboseLog bool
	Addr       string
	Port       int
	SSHVersion string
	PrivKey    string
	Timeout    time.Duration
	Debug      bool
	LogDir     string
}

var (
	cliArgument CliArgument
	logger      *zap.Logger
)

func init() {
	pflag.BoolVarP(&cliArgument.Debug, "debug", "d", false, "Enable debug mode")
	pflag.BoolVarP(&cliArgument.VerboseLog, "verbose", "v", false, "Enable verbose logging")
	pflag.StringVarP(&cliArgument.Addr, "address", "a", "127.0.0.1:2222", "Listen `address`")
	pflag.StringVarP(&cliArgument.SSHVersion, "version", "V", "SSH-2.0-OpenSSH_7.0", "SSH server `version` string")
	pflag.StringVarP(&cliArgument.PrivKey, "key", "k", "slp_id_rsa", "SSH private key `file`, which will be created if it "+"doesn't already exist")
	pflag.DurationVarP(&cliArgument.Timeout, "timeout", "t", time.Minute, "SSH handshake `timeout`")
	pflag.StringVarP(&cliArgument.LogDir, "log", "l", "./", "Log output dir")
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %v [options]\n\nOptions are:\n", os.Args[0])
		pflag.PrintDefaults()
		os.Exit(0)
	}
}

func main() {
	pflag.Parse()
	var (
		err   error
		level = zap.NewAtomicLevel()
	)

	if cliArgument.VerboseLog || cliArgument.Debug {
		level.SetLevel(zap.DebugLevel)
	}

	logFile, err := os.OpenFile(path.Join(cliArgument.LogDir, "sshlowpot.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()

	if cliArgument.Debug {
		logger = zap.New(
			zapcore.NewTee(
				zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), zapcore.Lock(os.Stderr), level),
				zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewDevelopmentEncoderConfig()), zapcore.Lock(logFile), level),
			),
			zap.WithCaller(true),
			zap.AddStacktrace(zap.ErrorLevel),
		)
	} else {
		logger = zap.New(
			zapcore.NewTee(
				zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()), zapcore.Lock(os.Stderr), level),
				zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.Lock(logFile), level),
			),
			zap.AddStacktrace(zap.ErrorLevel),
		)
	}

	// High-resolution logging
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Server Config
	conf, err := serverConfig(cliArgument.SSHVersion, cliArgument.PrivKey)
	if nil != err {
		log.Fatalf("Unable to generate server config: %v", err)
	}

	// Listen on the address
	l, err := net.Listen("tcp", cliArgument.Addr)
	if nil != err {
		log.Fatalf("Unable to listen on %v: %v", cliArgument.Addr, err)
	}
	logger.Sugar().Infof("Listening on %v", l.Addr())

	// Pop off connections, handle them
	for {
		c, err := l.Accept()
		if nil != err {
			log.Fatalf("Unable to accept new connection: %v", err)
		}
		go handle(c, conf, cliArgument.Timeout)
	}
}

// serverConfig makes an SSH server config struct with server version string
// sv and private key from file named pkf.
func serverConfig(sv, pkf string) (*ssh.ServerConfig, error) {
	// Config to return
	c := &ssh.ServerConfig{
		// Log authentication
		PasswordCallback:  logPass,
		PublicKeyCallback: logPubKey,

		// Server Version string
		ServerVersion: sv,
	}

	// Try to open the private key file
	privateKeyFile, err := os.OpenFile(pkf, os.O_RDWR|os.O_CREATE, 0o600)
	if nil != err {
		return nil, err
	}
	defer privateKeyFile.Close()

	// Read the file's contents
	pkb, err := io.ReadAll(privateKeyFile)
	if nil != err {
		return nil, err
	}

	// If the file was empty, make a key, write the file
	if len(pkb) == 0 {
		logger.Sugar().Debugf("No private key in %v, making new key...", privateKeyFile.Name())
		pkb, err = makeKeyInFile(privateKeyFile)
		if nil != err {
			return nil, err
		}
		logger.Sugar().Debugf("Made SSH key and wrote it to %v", privateKeyFile.Name())
	} else {
		logger.Sugar().Debugf("Read SSH key file %v", pkf)
	}

	// Parse the key
	pk, err := ssh.ParsePrivateKey(pkb)
	if nil != err {
		return nil, err
	}

	// Add it to the config
	c.AddHostKey(pk)

	// Return the config
	return c, nil
}

// makeKeyInFile makes a private SSH key and writes it to the file f, and
// returns what it wrote to the file.
func makeKeyInFile(f *os.File) ([]byte, error) {
	// Below code mooched from
	// http://stackoverflow.com/questions/21151714/go-generate-an-ssh-public-key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Encode the key
	pkb := pem.EncodeToMemory(privateKeyPEM)

	// Try to write it to the file
	if _, err := f.Write(pkb); nil != err {
		return nil, err
	}

	// Return the bytes
	return pkb, nil
}

// logPass logs a password attempt (and returns failure)
func logPass(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	logger.With(
		zap.String("user", conn.User()),
		zap.ByteString("password", password),
		zap.String("peer", conn.RemoteAddr().String()),
		zap.Any("ssh", map[string]interface{}{
			"user":           conn.User(),
			"session_id":     conn.SessionID(),
			"client_version": conn.ClientVersion(),
			"server_version": conn.ServerVersion(),
			"remote_addr":    conn.RemoteAddr().String(),
			"local_addr":     conn.LocalAddr().String(),
		}),
	).Info("Catch login attempt")
	return nil, fmt.Errorf("invalid password")
}

// logPubKey logs a public key attempt
func logPubKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	logger.With(
		zap.String("publickey", hex.EncodeToString(key.Marshal())),
		zap.String("user", conn.User()),
		zap.String("peer", conn.RemoteAddr().String()),
		zap.Any("ssh", map[string]interface{}{
			"user":           conn.User(),
			"session_id":     base64.StdEncoding.EncodeToString(conn.SessionID()),
			"client_version": base64.StdEncoding.EncodeToString(conn.ClientVersion()),
			"server_version": base64.StdEncoding.EncodeToString(conn.ServerVersion()),
			"remote_addr":    conn.RemoteAddr().String(),
			"local_addr":     conn.LocalAddr().String(),
		}),
		zap.ByteString("ssh-version", conn.ClientVersion()),
	).Info("Catch login attempt")
	// logger.Sugar().Infof("%v Key(%v):%02X", ci(conn), key.Type(), md5.Sum(key.Marshal()))
	return nil, fmt.Errorf("invalid key")
}

// ci returns a string containing info from an ssh.ConnMetadata
func ci(m ssh.ConnMetadata) string {
	return fmt.Sprintf("Address:%v Version:%q User:%q", m.RemoteAddr(), m.ClientVersion(), m.User())
}

// handle handles a new connection
func handle(c net.Conn, conf *ssh.ServerConfig, timeout time.Duration) {
	defer c.Close()
	logger.Sugar().Debugf("Address:%v Connect", c.RemoteAddr())

	ch := make(chan struct{}, 1)

	// Try to upgrade to an SSH connection
	go func(c net.Conn, conf *ssh.ServerConfig, ch chan<- struct{}) {
		sc, _, _, err := ssh.NewServerConn(c, conf)
		if nil == err { // This should be the norm
			logger.Sugar().Infof("%v authenticated successfully, killing. This shouldn't happen.", ci(sc))
		}
		ch <- struct{}{}
	}(c, conf, ch)

	// Wait for the upgrade (and auth fails) or a timeout
	select {
	case <-ch:
		logger.Sugar().Debugf("Address:%v Disconnect", c.RemoteAddr())
	case <-time.After(timeout):
		logger.Sugar().Debugf("Address:%v Handshake timeout", c.RemoteAddr())
	}
}
