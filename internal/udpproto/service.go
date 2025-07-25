package udpproto

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"zcdns-tunnel/internal/common"
)

const (
	// DefaultMessageTimeout adalah waktu maksimum untuk menunggu respons
	DefaultMessageTimeout = 5 * time.Second
	// DefaultMessageMaxAge adalah usia maksimum pesan yang valid
	DefaultMessageMaxAge = 10 * time.Second
	// DefaultUDPPort adalah port default untuk komunikasi UDP
	DefaultUDPPort = 7946
)

// Config adalah konfigurasi untuk UDPService
type Config struct {
	ListenAddr    string
	ClusterSecret string
	MessageMaxAge time.Duration
}

// UDPService mengelola komunikasi antar node menggunakan protokol UDP kustom
type UDPService struct {
	config      Config
	localAddr   string
	conn        *net.UDPConn
	handlers    map[string]MessageHandler
	pendingResp map[string]chan *Message
	secret      []byte
	stopChan    chan struct{}
	wg          sync.WaitGroup
	mu          sync.RWMutex
}

// MessageHandler adalah fungsi untuk menangani pesan yang diterima
type MessageHandler func(ctx context.Context, msg *Message) (*Message, error)

// NewUDPService membuat instance UDPService baru
func NewUDPService(config Config, localAddr string) *UDPService {
	if config.MessageMaxAge == 0 {
		config.MessageMaxAge = DefaultMessageMaxAge
	}

	return &UDPService{
		config:      config,
		localAddr:   localAddr,
		handlers:    make(map[string]MessageHandler),
		pendingResp: make(map[string]chan *Message),
		secret:      []byte(config.ClusterSecret),
		stopChan:    make(chan struct{}),
	}
}

// Start memulai service UDP
func (s *UDPService) Start(ctx context.Context) error {
	// Selalu gunakan port 7946 (DefaultUDPPort) untuk komunikasi UDP
	listenAddr := fmt.Sprintf(":%d", DefaultUDPPort)
	
	logrus.Infof("UDP service akan menggunakan port: %s", listenAddr)
	
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("gagal resolve alamat UDP: %w", err)
	}

	// Implement retry with exponential backoff
	var conn *net.UDPConn
	var lastErr error
	
	for retries := 0; retries < 5; retries++ {
		conn, err = net.ListenUDP("udp", addr)
		if err == nil {
			break // Successfully established connection
		}
		
		lastErr = err
		
		// Check if this is a temporary error that might resolve with retry
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Temporary() {
				backoffTime := time.Duration(1<<uint(retries)) * 100 * time.Millisecond
				logrus.Warnf("Temporary error listening on UDP port %d, retrying in %v: %v", 
					DefaultUDPPort, backoffTime, err)
				time.Sleep(backoffTime)
				continue
			}
		}
		
		// Non-temporary error, no need to retry
		return fmt.Errorf("gagal listen UDP pada port %d: %w", DefaultUDPPort, err)
	}
	
	if conn == nil {
		return fmt.Errorf("gagal listen UDP setelah beberapa percobaan: %w", lastErr)
	}
	
	s.config.ListenAddr = listenAddr
	s.conn = conn
	logrus.Infof("UDP service listening on %s", s.config.ListenAddr)

	s.wg.Add(1)
	go s.listenForMessages(ctx)

	return nil
}

// Stop menghentikan service UDP
func (s *UDPService) Stop() {
	logrus.Info("Stopping UDP service...")
	close(s.stopChan)
	if s.conn != nil {
		s.conn.Close()
	}
	s.wg.Wait()
	logrus.Info("UDP service stopped.")
}

// RegisterHandler mendaftarkan handler untuk tipe pesan tertentu
func (s *UDPService) RegisterHandler(msgType string, handler MessageHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[msgType] = handler
}

// SendMessage mengirim pesan ke alamat tujuan dan menunggu respons
func (s *UDPService) SendMessage(ctx context.Context, msg *Message, targetAddr string) (*Message, error) {
	// Tandatangani pesan
	if err := msg.Sign(s.secret); err != nil {
		return nil, fmt.Errorf("gagal menandatangani pesan: %w", err)
	}

	// Buat channel untuk respons
	respChan := make(chan *Message, 1)
	respKey := fmt.Sprintf("%s-%d", msg.Type, msg.Timestamp)

	s.mu.Lock()
	s.pendingResp[respKey] = respChan
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.pendingResp, respKey)
		s.mu.Unlock()
	}()

	// Kirim pesan dengan retry untuk mengatasi packet loss dan network issues
	maxRetries := 3
	for i := 0; i <= maxRetries; i++ {
		// Jika ini bukan percobaan pertama, tunggu sebentar sebelum mencoba lagi
		if i > 0 {
			backoffTime := time.Duration(i) * 200 * time.Millisecond
			logrus.Debugf("Retry %d sending message to %s (backoff: %v)", i, targetAddr, backoffTime)
			select {
			case <-time.After(backoffTime):
				// Lanjutkan setelah backoff
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		
		// Kirim pesan
		err := s.sendMessageRaw(msg, targetAddr)
		if err != nil {
			if i == maxRetries {
				return nil, fmt.Errorf("gagal mengirim pesan ke %s setelah %d percobaan: %w", targetAddr, maxRetries+1, err)
			}
			
			logrus.Warnf("Failed to send message to %s (attempt %d/%d): %v", targetAddr, i+1, maxRetries+1, err)
			
			// Tidak perlu mencoba port alternatif, tetap gunakan port yang sama
			continue
		}
		
		// Tunggu respons atau timeout
		timeoutDuration := getTimeoutFromContext(ctx, DefaultMessageTimeout)
		select {
		case resp := <-respChan:
			return resp, nil
		case <-time.After(timeoutDuration):
			if i == maxRetries {
				return nil, fmt.Errorf("timeout menunggu respons dari %s setelah %d percobaan", targetAddr, maxRetries+1)
			}
			logrus.Warnf("Timeout waiting for response from %s (attempt %d/%d)", targetAddr, i+1, maxRetries+1)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	
	// Jika kita sampai di sini, semua retry telah gagal
	return nil, fmt.Errorf("timeout menunggu respons dari %s setelah %d percobaan", targetAddr, maxRetries+1)
}

// getTimeoutFromContext mendapatkan timeout dari context atau menggunakan default
func getTimeoutFromContext(ctx context.Context, defaultTimeout time.Duration) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return defaultTimeout
	}
	
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return time.Millisecond // Minimal timeout
	}
	
	return remaining
}

// SendMessageWithoutResponse mengirim pesan tanpa menunggu respons
func (s *UDPService) SendMessageWithoutResponse(msg *Message, targetAddr string) error {
	// Tandatangani pesan
	if err := msg.Sign(s.secret); err != nil {
		return fmt.Errorf("gagal menandatangani pesan: %w", err)
	}

	// Kirim pesan
	return s.sendMessageRaw(msg, targetAddr)
}

// sendMessageRaw mengirim pesan mentah ke alamat tujuan
func (s *UDPService) sendMessageRaw(msg *Message, targetAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return fmt.Errorf("gagal resolve alamat target %s: %w", targetAddr, err)
	}

	// Serialize pesan
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("gagal serialize pesan: %w", err)
	}

	// Implement retry with exponential backoff
	maxRetries := 3
	for retry := 0; retry < maxRetries; retry++ {
		// Add backoff delay for retries
		if retry > 0 {
			backoffTime := time.Duration(1<<uint(retry-1)) * 200 * time.Millisecond
			logrus.Debugf("Retrying UDP send to %s (attempt %d/%d) after %v", targetAddr, retry+1, maxRetries, backoffTime)
			time.Sleep(backoffTime)
		}
		
		// Set write deadline untuk menghindari blocking selamanya
		s.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		
		// Kirim pesan
		_, err = s.conn.WriteToUDP(msgBytes, addr)
		
		// Reset write deadline
		s.conn.SetWriteDeadline(time.Time{})
		
		if err == nil {
			// Message sent successfully
			return nil
		}
		
		// Handle different error types
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			logrus.Warnf("Timeout saat mengirim pesan ke %s (attempt %d/%d), will retry", 
				targetAddr, retry+1, maxRetries)
		} else if opErr, ok := err.(*net.OpError); ok {
			if strings.Contains(opErr.Error(), "connection refused") {
				logrus.Warnf("Koneksi ditolak saat mengirim pesan ke %s (attempt %d/%d)", 
					targetAddr, retry+1, maxRetries)
			} else if strings.Contains(opErr.Error(), "network is unreachable") {
				logrus.Warnf("Jaringan tidak dapat dijangkau saat mengirim pesan ke %s (attempt %d/%d)", 
					targetAddr, retry+1, maxRetries)
			} else {
				logrus.Warnf("Error mengirim pesan ke %s (attempt %d/%d): %v", 
					targetAddr, retry+1, maxRetries, err)
			}
		} else {
			logrus.Warnf("Unknown error mengirim pesan ke %s (attempt %d/%d): %v", 
				targetAddr, retry+1, maxRetries, err)
		}
		
		// Last retry failed
		if retry == maxRetries-1 {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return fmt.Errorf("timeout saat mengirim pesan ke %s setelah %d percobaan", 
					targetAddr, maxRetries)
			} else if opErr, ok := err.(*net.OpError); ok {
				if strings.Contains(opErr.Error(), "connection refused") {
					return fmt.Errorf("koneksi ditolak saat mengirim pesan ke %s setelah %d percobaan", 
						targetAddr, maxRetries)
				} else if strings.Contains(opErr.Error(), "network is unreachable") {
					return fmt.Errorf("jaringan tidak dapat dijangkau saat mengirim pesan ke %s setelah %d percobaan", 
						targetAddr, maxRetries)
				}
			}
			return fmt.Errorf("gagal kirim pesan ke %s setelah %d percobaan: %w", 
				targetAddr, maxRetries, err)
		}
	}
	
	// This should never be reached due to the return in the last retry case
	return fmt.Errorf("gagal kirim pesan ke %s: unexpected error", targetAddr)
}

// listenForMessages mendengarkan pesan UDP yang masuk.
func (s *UDPService) listenForMessages(ctx context.Context) {
	defer s.wg.Done()
	buf := make([]byte, 65536) // Ukuran buffer UDP maksimum

	for {
		select {
		case <-s.stopChan:
			return
		case <-ctx.Done():
			return
		default:
			// Set read deadline untuk menghindari blocking selamanya
			s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, remoteAddr, err := s.conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout, ini normal dan bukan error sebenarnya
					continue
				}
				
				// Untuk error lain, log dengan level debug saja untuk menghindari spam log
				if opErr, ok := err.(*net.OpError); ok {
					// Check for specific network errors that might be temporary
					if opErr.Temporary() {
						logrus.Debugf("Temporary UDP read error in UDP service: %s (%T)", opErr.Error(), opErr.Err)
					} else {
						// Log dengan detail tipe error untuk debugging
						logrus.Debugf("UDP service read error: %s (%T)", opErr.Error(), opErr.Err)
					}
				} else {
					logrus.Debugf("Non-timeout error reading from UDP in UDP service: %v", err)
				}
				continue
			}

			// Reset read deadline
			s.conn.SetReadDeadline(time.Time{})
			
			// Proses pesan dalam goroutine terpisah untuk menghindari blocking
			msgCopy := make([]byte, n)
			copy(msgCopy, buf[:n])
			go s.handleMessage(ctx, msgCopy, remoteAddr)
		}
	}
}

// handleMessage memproses pesan yang diterima
func (s *UDPService) handleMessage(ctx context.Context, msgBytes []byte, remoteAddr *net.UDPAddr) {
	// Parse pesan
	msg, err := ParseMessage(msgBytes)
	if err != nil {
		logrus.Warnf("Gagal parse pesan dari %s: %v", remoteAddr.String(), err)
		return
	}

	// Verifikasi tanda tangan
	if !msg.Verify(s.secret) {
		logrus.Warnf("Verifikasi tanda tangan gagal untuk pesan dari %s", remoteAddr.String())
		return
	}

	// Periksa kadaluarsa
	if msg.IsExpired(s.config.MessageMaxAge) {
		logrus.Warnf("Pesan kadaluarsa dari %s", remoteAddr.String())
		return
	}

	// Periksa apakah ini adalah respons untuk pesan yang tertunda
	respKey := fmt.Sprintf("%s-%d", msg.Type, msg.Timestamp)
	s.mu.RLock()
	respChan, isPendingResp := s.pendingResp[respKey]
	s.mu.RUnlock()

	if isPendingResp {
		respChan <- msg
		return
	}

	// Jika bukan respons, proses sebagai pesan baru
	s.mu.RLock()
	handler, exists := s.handlers[msg.Type]
	s.mu.RUnlock()

	if !exists {
		// Jika tidak ada handler untuk tipe pesan ini, kirim respons error
		logrus.Warnf("Tidak ada handler untuk tipe pesan %s dari %s", msg.Type, remoteAddr.String())
		
		// Untuk pesan yang memerlukan respons, kirim respons error
		if msg.Type == MessageTypeForward {
			// Buat respons error untuk pesan forward
			var payload ForwardPayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				logrus.Warnf("Gagal unmarshal payload forward: %v", err)
				return
			}
			
			errPayload := ForwardResponsePayload{
				ForwardID: payload.ForwardID,
				Success:   false,
				Error:     fmt.Sprintf("Tidak ada handler untuk tipe pesan %s", msg.Type),
			}
			
			respMsg, err := NewMessage(MessageTypeForwardResponse, s.localAddr, errPayload)
			if err != nil {
				logrus.Errorf("Gagal membuat pesan respons error: %v", err)
				return
			}
			
			if err := respMsg.Sign(s.secret); err != nil {
				logrus.Errorf("Gagal menandatangani respons error: %v", err)
				return
			}
			
			respBytes, err := json.Marshal(respMsg)
			if err != nil {
				logrus.Errorf("Gagal serialize respons error: %v", err)
				return
			}
			
			if _, err := s.conn.WriteToUDP(respBytes, remoteAddr); err != nil {
				logrus.Errorf("Gagal kirim respons error ke %s: %v", remoteAddr.String(), err)
			}
		}
		
		return
	}

	// Panggil handler
	resp, err := handler(ctx, msg)
	if err != nil {
		logrus.Errorf("Error menangani pesan %s dari %s: %v", msg.Type, remoteAddr.String(), err)
		return
	}

	// Jika handler mengembalikan respons, kirim kembali ke pengirim
	if resp != nil {
		resp.Sender = s.localAddr
		if err := resp.Sign(s.secret); err != nil {
			logrus.Errorf("Gagal menandatangani respons: %v", err)
			return
		}

		respBytes, err := json.Marshal(resp)
		if err != nil {
			logrus.Errorf("Gagal serialize respons: %v", err)
			return
		}

		if _, err := s.conn.WriteToUDP(respBytes, remoteAddr); err != nil {
			logrus.Errorf("Gagal kirim respons ke %s: %v", remoteAddr.String(), err)
		}
	}
}
// GetListenAddr mengembalikan alamat yang digunakan untuk mendengarkan
func (s *UDPService) GetListenAddr() string {
	return s.config.ListenAddr
}
// UDPServiceFromGossip membuat instance UDPService yang menggunakan koneksi UDP dari GossipService
func UDPServiceFromGossip(provider common.UDPProvider, clusterSecret string) *UDPService {
	// Always use the DefaultUDPPort (7946) for consistency
	listenAddr := fmt.Sprintf(":%d", DefaultUDPPort)
	
	config := Config{
		ListenAddr:    listenAddr,
		ClusterSecret: clusterSecret,
		MessageMaxAge: DefaultMessageMaxAge,
	}
	
	service := &UDPService{
		config:      config,
		localAddr:   provider.GetLocalAddr(),
		conn:        provider.GetUDPConn(), // Gunakan koneksi UDP yang sama dengan GossipService
		handlers:    make(map[string]MessageHandler),
		pendingResp: make(map[string]chan *Message),
		secret:      []byte(clusterSecret),
		stopChan:    make(chan struct{}),
	}
	
	// Log the shared connection details for debugging
	if service.conn != nil {
		logrus.Infof("UDPService sharing UDP connection from gossip service at local address: %s", service.conn.LocalAddr().String())
	} else {
		logrus.Warnf("UDPService received nil UDP connection from gossip service")
	}
	
	return service
}
// StartWithExistingConn memulai service UDP dengan koneksi yang sudah ada
func (s *UDPService) StartWithExistingConn(ctx context.Context) error {
	// Pastikan koneksi sudah ada
	if s.conn == nil {
		return fmt.Errorf("koneksi UDP tidak tersedia")
	}
	
	// Make sure we're using the correct port in our configuration
	s.config.ListenAddr = fmt.Sprintf(":%d", DefaultUDPPort)
	
	logrus.Infof("UDP service menggunakan koneksi UDP yang sama dengan gossip service pada %s", s.config.ListenAddr)
	
	// Set up a separate goroutine for listening to messages
	// This is important even though the gossip service is also listening on the same connection
	// because we need to handle UDP protocol specific messages
	s.wg.Add(1)
	go s.listenForMessages(ctx)
	
	return nil
}
// GetUDPConn mengembalikan koneksi UDP yang digunakan oleh service
func (s *UDPService) GetUDPConn() *net.UDPConn {
	return s.conn
}