export async function sendVerificationEmail(env, to, token) {
  const verifyUrl = `${env.APP_URL}/api/auth/verify?token=${token}`;

  await sendEmail(env, {
    to,
    subject: 'メールアドレスの認証 - Zig Auth',
    html: `
      <h2>メールアドレスの認証</h2>
      <p>以下のリンクをクリックしてメールアドレスを認証してください。</p>
      <p><a href="${verifyUrl}" style="display:inline-block;padding:12px 24px;background:#2563eb;color:#fff;text-decoration:none;border-radius:8px;">認証する</a></p>
      <p>このリンクは24時間有効です。</p>
      <p style="color:#666;font-size:12px;">このメールに心当たりがない場合は無視してください。</p>
    `,
  });
}

export async function sendPasswordResetEmail(env, to, token) {
  const resetUrl = `${env.FRONTEND_URL}/reset-password?token=${token}`;

  await sendEmail(env, {
    to,
    subject: 'パスワードリセット - Zig Auth',
    html: `
      <h2>パスワードリセット</h2>
      <p>以下のリンクからパスワードをリセットしてください。</p>
      <p><a href="${resetUrl}" style="display:inline-block;padding:12px 24px;background:#2563eb;color:#fff;text-decoration:none;border-radius:8px;">パスワードをリセット</a></p>
      <p>このリンクは1時間有効です。</p>
      <p style="color:#666;font-size:12px;">このメールに心当たりがない場合は無視してください。</p>
    `,
  });
}

async function sendEmail(env, { to, subject, html }) {
  // Cloudflare Email Service (beta) binding
  if (env.EMAIL) {
    await env.EMAIL.send({
      from: env.EMAIL_FROM || 'noreply@example.com',
      to,
      subject,
      html,
    });
    return;
  }

  // Fallback: Resend API
  if (env.RESEND_API_KEY) {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: env.EMAIL_FROM || 'noreply@example.com',
        to,
        subject,
        html,
      }),
    });
    return;
  }

  // Dev mode: log to console
  console.log(`[EMAIL] To: ${to}, Subject: ${subject}`);
  console.log(`[EMAIL] Would send HTML email`);
}
