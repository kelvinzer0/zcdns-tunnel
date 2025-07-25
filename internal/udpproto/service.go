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
	// Ekstrak port dari localAddr jika ada
	_, port, err := net.SplitHostPort(s.localAddr)
	if err != nil {
		// Jika tidak bisa di-parse, gunakan port default
		port = fmt.Sprintf("%d", DefaultUDPPort)
	}

	// Gunakan port yang sama dengan gossip service untuk menghindari konflik
	listenAddr := fmt.Sprintf(":%s", port)
	
	logrus.Infof("UDP service akan menggunakan port yang sama dengan gossip service: %s", listenAddr)
	
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("gagal resolve alamat UDP: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		// Jika gagal mendengarkan pada port yang sama, gunakan port alternatif
		altPort := DefaultUDPPort + 1000 // Gunakan port alternatif (misalnya 8946)
		altListenAddr := fmt.Sprintf(":%d", altPort)
		logrus.Warnf("Gagal listen pada port %s, mencoba port alternatif %s", listenAddr, altListenAddr)
		
		altAddr, err := net.ResolveUDPAddr("udp", altListenAddr)
		if err != nil {
			return fmt.Errorf("gagal resolve alamat UDP alternatif: %w", err)
		}
		
		conn, err = net.ListenUDP("udp", altAddr)
		if err != nil {
			return fmt.Errorf("gagal listen UDP pada port alternatif: %w", err)
		}
		
		// Update listenAddr ke port yang berhasil
		s.config.ListenAddr = altListenAddr
	} else {
		s.config.ListenAddr = listenAddr
	}
	
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

	// Kirim pesan dengan retry untuk mengatasi packet loss
	maxRetries := 2
	for i := 0; i <= maxRetries; i++ {
		// Jika ini bukan percobaan pertama, tunggu sebentar sebelum mencoba lagi
		if i > 0 {
			time.Sleep(time.Duration(i) * 200 * time.Millisecond)
			logrus.Debugf("Retry %d sending message to %s", i, targetAddr)
		}
		
		// Kirim pesan
		if err := s.sendMessageRaw(msg, targetAddr); err != nil {
			if i == maxRetries {
				return nil, err
			}
			logrus.Warnf("Failed to send message to %s (attempt %d/%d): %v", targetAddr, i+1, maxRetries+1, err)
			continue
		}
		
		// Tunggu respons atau timeout
		timeoutChan := time.After(getTimeoutFromContext(ctx, DefaultMessageTimeout))
		select {
		case resp := <-respChan:
			return resp, nil
		case <-timeoutChan:
			if i == maxRetries {
				return nil, fmt.Errorf("timeout menunggu respons dari %s", targetAddr)
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

	// Set write deadline untuk menghindari blocking selamanya
	s.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	
	// Kirim pesan
	_, err = s.conn.WriteToUDP(msgBytes, addr)
	
	// Reset write deadline
	s.conn.SetWriteDeadline(time.Time{})
	
	if err != nil {
		// Periksa apakah error adalah timeout atau connection refused
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return fmt.Errorf("timeout saat mengirim pesan ke %s", targetAddr)
		} else if opErr, ok := err.(*net.OpError); ok && strings.Contains(opErr.Error(), "connection refused") {
			return fmt.Errorf("koneksi ditolak saat mengirim pesan ke %s", targetAddr)
		}
		return fmt.Errorf("gagal kirim pesan ke %s: %w", targetAddr, err)
	}

	return nil
}

// listenForMessages mendengarkan pesan yang masuk
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
					// Timeout, lanjutkan loop
					continue
				}
				logrus.Errorf("Error membaca dari UDP: %v", err)
				continue
			}

			// Proses pesan dalam goroutine terpisah
			go s.handleMessage(ctx, buf[:n], remoteAddr)
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
		logrus.Warnf("Tidak ada handler untuk tipe pesan %s dari %s", msg.Type, remoteAddr.String())
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