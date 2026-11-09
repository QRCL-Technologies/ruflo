/**
 * @claude-flow/mcp - WebSocket Transport
 *
 * Standalone WebSocket transport with heartbeat
 */

import { EventEmitter } from 'events';
import { WebSocketServer, WebSocket, RawData } from 'ws';
import { createServer, Server, IncomingMessage } from 'http';
import { createHash, timingSafeEqual } from 'crypto';
import type {
  ITransport,
  TransportType,
  MCPRequest,
  MCPResponse,
  MCPNotification,
  RequestHandler,
  NotificationHandler,
  TransportHealthStatus,
  ILogger,
  AuthConfig,
} from '../types.js';

export interface WebSocketTransportConfig {
  host: string;
  port: number;
  path?: string;
  maxConnections?: number;
  heartbeatInterval?: number;
  heartbeatTimeout?: number;
  maxMessageSize?: number;
  auth?: AuthConfig;
  enableBinaryMode?: boolean;
  /**
   * Browser origins allowed to open a connection. Requests carrying any other
   * Origin header are rejected during the handshake; an empty list (the
   * default) rejects every browser origin. Non-browser clients send no Origin.
   */
  allowedOrigins?: string[];
}

interface ClientConnection {
  id: string;
  ws: WebSocket;
  createdAt: Date;
  lastActivity: Date;
  messageCount: number;
  isAlive: boolean;
  isAuthenticated: boolean;
}

export class WebSocketTransport extends EventEmitter implements ITransport {
  public readonly type: TransportType = 'websocket';

  private requestHandler?: RequestHandler;
  private notificationHandler?: NotificationHandler;
  private server?: Server;
  private wss?: WebSocketServer;
  private clients: Map<string, ClientConnection> = new Map();
  private heartbeatTimer?: NodeJS.Timeout;
  private running = false;
  private connectionCounter = 0;

  private messagesReceived = 0;
  private messagesSent = 0;
  private errors = 0;
  private totalConnections = 0;

  constructor(
    private readonly logger: ILogger,
    private readonly config: WebSocketTransportConfig
  ) {
    super();
  }

  async start(): Promise<void> {
    if (this.running) {
      throw new Error('WebSocket transport already running');
    }

    this.logger.info('Starting WebSocket transport', {
      host: this.config.host,
      port: this.config.port,
      path: this.config.path || '/ws',
    });

    this.server = createServer((req, res) => {
      res.writeHead(426, { 'Content-Type': 'text/plain' });
      res.end('Upgrade Required - WebSocket connection expected');
    });

    this.wss = new WebSocketServer({
      server: this.server,
      path: this.config.path || '/ws',
      maxPayload: this.config.maxMessageSize || 10 * 1024 * 1024,
      perMessageDeflate: true,
      verifyClient: (info, callback) => this.verifyClient(info.req, callback),
    });

    this.setupWebSocketHandlers();
    this.startHeartbeat();

    await new Promise<void>((resolve, reject) => {
      this.server!.listen(this.config.port, this.config.host, () => {
        resolve();
      });
      this.server!.on('error', reject);
    });

    this.running = true;
    this.logger.info('WebSocket transport started', {
      url: `ws://${this.config.host}:${this.config.port}${this.config.path || '/ws'}`,
    });
  }

  async stop(): Promise<void> {
    if (!this.running) {
      return;
    }

    this.logger.info('Stopping WebSocket transport');
    this.running = false;

    this.stopHeartbeat();

    for (const client of this.clients.values()) {
      try {
        client.ws.close(1000, 'Server shutting down');
      } catch {
        // Ignore errors
      }
    }
    this.clients.clear();

    if (this.wss) {
      this.wss.close();
      this.wss = undefined;
    }

    if (this.server) {
      await new Promise<void>((resolve) => {
        this.server!.close(() => resolve());
      });
      this.server = undefined;
    }

    this.logger.info('WebSocket transport stopped');
  }

  onRequest(handler: RequestHandler): void {
    this.requestHandler = handler;
  }

  onNotification(handler: NotificationHandler): void {
    this.notificationHandler = handler;
  }

  async getHealthStatus(): Promise<TransportHealthStatus> {
    return {
      healthy: this.running,
      metrics: {
        messagesReceived: this.messagesReceived,
        messagesSent: this.messagesSent,
        errors: this.errors,
        activeConnections: this.clients.size,
        totalConnections: this.totalConnections,
      },
    };
  }

  async sendNotification(notification: MCPNotification): Promise<void> {
    const message = this.serializeMessage(notification);

    for (const client of this.clients.values()) {
      try {
        if (client.ws.readyState === WebSocket.OPEN) {
          client.ws.send(message);
          this.messagesSent++;
        }
      } catch (error) {
        this.logger.error('Failed to send notification', { clientId: client.id, error });
        this.errors++;
      }
    }
  }

  async sendToClient(clientId: string, notification: MCPNotification): Promise<boolean> {
    const client = this.clients.get(clientId);
    if (!client || client.ws.readyState !== WebSocket.OPEN) {
      return false;
    }

    try {
      client.ws.send(this.serializeMessage(notification));
      this.messagesSent++;
      return true;
    } catch (error) {
      this.logger.error('Failed to send to client', { clientId, error });
      this.errors++;
      return false;
    }
  }

  getClients(): string[] {
    return Array.from(this.clients.keys());
  }

  getClientInfo(clientId: string): ClientConnection | undefined {
    return this.clients.get(clientId);
  }

  disconnectClient(clientId: string, reason = 'Disconnected by server'): boolean {
    const client = this.clients.get(clientId);
    if (!client) {
      return false;
    }

    try {
      client.ws.close(1000, reason);
      return true;
    } catch {
      return false;
    }
  }

  private setupWebSocketHandlers(): void {
    if (!this.wss) return;

    this.wss.on('connection', (ws) => {
      if (this.config.maxConnections && this.clients.size >= this.config.maxConnections) {
        this.logger.warn('Max connections reached, rejecting client');
        ws.close(1013, 'Server at capacity');
        return;
      }

      const clientId = `client-${++this.connectionCounter}`;
      const client: ClientConnection = {
        id: clientId,
        ws,
        createdAt: new Date(),
        lastActivity: new Date(),
        messageCount: 0,
        isAlive: true,
        // verifyClient already rejected the handshake unless it was authorized.
        isAuthenticated: true,
      };

      this.clients.set(clientId, client);
      this.totalConnections++;

      this.logger.info('Client connected', {
        id: clientId,
        total: this.clients.size,
      });

      ws.on('message', async (data) => {
        await this.handleMessage(client, data);
      });

      ws.on('pong', () => {
        client.isAlive = true;
      });

      ws.on('close', (code, reason) => {
        this.clients.delete(clientId);
        this.logger.info('Client disconnected', {
          id: clientId,
          code,
          reason: reason.toString(),
          total: this.clients.size,
        });
        this.emit('client:disconnected', clientId);
      });

      ws.on('error', (error) => {
        this.logger.error('Client error', { id: clientId, error });
        this.errors++;
        this.clients.delete(clientId);
      });

      this.emit('client:connected', clientId);
    });
  }

  /**
   * SECURITY: handshake gate. Rejects cross-site WebSocket hijacking (any
   * browser Origin not explicitly allowed) and, when auth is enabled, any
   * upgrade without a valid `Authorization: Bearer <token>` header.
   */
  private verifyClient(
    req: IncomingMessage,
    callback: (result: boolean, code?: number, message?: string) => void
  ): void {
    const origin = req.headers.origin;
    if (origin !== undefined && !this.isOriginAllowed(origin)) {
      this.logger.warn('WebSocket connection rejected: origin not allowed', { origin });
      callback(false, 403, 'Forbidden');
      return;
    }

    if (this.config.auth?.enabled && !this.isAuthorized(req)) {
      // Never log the Authorization header or any token material.
      this.logger.warn('WebSocket connection rejected: authentication failed');
      callback(false, 401, 'Unauthorized');
      return;
    }

    callback(true);
  }

  private isOriginAllowed(origin: string): boolean {
    const allowed = this.config.allowedOrigins ?? [];
    const normalized = origin.trim().toLowerCase();
    return allowed.some((o) => o === '*' || o.trim().toLowerCase() === normalized);
  }

  private isAuthorized(req: IncomingMessage): boolean {
    const auth = req.headers.authorization;
    if (typeof auth !== 'string') {
      return false;
    }
    const tokenMatch = auth.match(/^Bearer\s+(.+)$/i);
    if (!tokenMatch) {
      return false;
    }

    // Fail closed: auth enabled with no configured token accepts nothing.
    const tokens = this.config.auth?.tokens ?? [];
    let valid = false;
    for (const validToken of tokens) {
      // No early exit, so timing does not depend on which token matched.
      if (this.timingSafeCompare(tokenMatch[1], validToken)) {
        valid = true;
      }
    }
    return valid;
  }

  /** Constant-time comparison over equal-length digests. */
  private timingSafeCompare(a: string, b: string): boolean {
    const digestA = createHash('sha256').update(a, 'utf8').digest();
    const digestB = createHash('sha256').update(b, 'utf8').digest();
    return timingSafeEqual(digestA, digestB);
  }

  private async handleMessage(client: ClientConnection, data: RawData): Promise<void> {
    client.lastActivity = new Date();
    client.messageCount++;
    this.messagesReceived++;

    try {
      const message = this.parseMessage(data);

      if (!client.isAuthenticated) {
        client.ws.send(this.serializeMessage({
          jsonrpc: '2.0',
          id: message.id || null,
          error: { code: -32001, message: 'Authentication required' },
        } as MCPResponse));
        return;
      }

      if (message.jsonrpc !== '2.0') {
        client.ws.send(this.serializeMessage({
          jsonrpc: '2.0',
          id: message.id || null,
          error: { code: -32600, message: 'Invalid JSON-RPC version' },
        } as MCPResponse));
        return;
      }

      if (message.id === undefined) {
        if (this.notificationHandler) {
          await this.notificationHandler(message as MCPNotification);
        }
      } else {
        if (!this.requestHandler) {
          client.ws.send(this.serializeMessage({
            jsonrpc: '2.0',
            id: message.id,
            error: { code: -32603, message: 'No request handler' },
          } as MCPResponse));
          return;
        }

        const startTime = performance.now();
        const response = await this.requestHandler(message as MCPRequest);
        const duration = performance.now() - startTime;

        this.logger.debug('Request processed', {
          clientId: client.id,
          method: message.method,
          duration: `${duration.toFixed(2)}ms`,
        });

        client.ws.send(this.serializeMessage(response));
        this.messagesSent++;
      }
    } catch (error) {
      this.errors++;
      this.logger.error('Message handling error', { clientId: client.id, error });

      try {
        client.ws.send(this.serializeMessage({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error' },
        } as MCPResponse));
      } catch {
        // Ignore send errors
      }
    }
  }

  private parseMessage(data: RawData): any {
    if (this.config.enableBinaryMode && Buffer.isBuffer(data)) {
      return JSON.parse(data.toString());
    }
    return JSON.parse(data.toString());
  }

  private serializeMessage(message: MCPResponse | MCPNotification): string | Buffer {
    if (this.config.enableBinaryMode) {
      return JSON.stringify(message);
    }
    return JSON.stringify(message);
  }

  private startHeartbeat(): void {
    const interval = this.config.heartbeatInterval || 30000;

    this.heartbeatTimer = setInterval(() => {
      for (const client of this.clients.values()) {
        if (!client.isAlive) {
          this.logger.warn('Client heartbeat timeout', { id: client.id });
          client.ws.terminate();
          this.clients.delete(client.id);
          continue;
        }

        client.isAlive = false;
        try {
          client.ws.ping();
        } catch {
          // Ignore ping errors
        }
      }
    }, interval);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
  }
}

export function createWebSocketTransport(
  logger: ILogger,
  config: WebSocketTransportConfig
): WebSocketTransport {
  return new WebSocketTransport(logger, config);
}
