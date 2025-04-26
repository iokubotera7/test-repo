// ユーザー認証機能の実装
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

class AuthService {
    constructor() {
        this.users = new Map();
        this.JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
    }

    // ユーザー登録
    async register(username, password) {
        if (this.users.has(username)) {
            throw new Error('ユーザーは既に存在します');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        this.users.set(username, {
            username,
            password: hashedPassword
        });

        return this.generateToken(username);
    }

    // ログイン
    async login(username, password) {
        const user = this.users.get(username);
        if (!user) {
            throw new Error('ユーザーが見つかりません');
        }

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            throw new Error('パスワードが正しくありません');
        }

        return this.generateToken(username);
    }

    // JWTトークンの生成
    generateToken(username) {
        return jwt.sign({ username }, this.JWT_SECRET, {
            expiresIn: '24h'
        });
    }

    // トークン検証
    verifyToken(token) {
        try {
            return jwt.verify(token, this.JWT_SECRET);
        } catch (error) {
            throw new Error('無効なトークンです');
        }
    }
}

module.exports = new AuthService();