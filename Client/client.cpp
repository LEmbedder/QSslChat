#include <QDateTime>
#include <QMessageBox>
#include "client.h"
#include "ui_client.h"

Client::Client(QWidget *parent) : QMainWindow(parent),  ui(new Ui::Client)
{
  ui->setupUi(this);

  //检查SSL是否支持，如果不支持会提示怎么使能支持
  if (QSslSocket::supportsSsl())
  {
    ui->connectDisconnectButton->setEnabled(true);
  }
  else
  {
    QString noSslMsg = QString("%1\n%2")
        .arg("*** Your version of Qt does support SSL ***")
        .arg("You must obtain a version of Qt that has SSL"
             "support enabled.  If you believe that your "
             "version of Qt has SSL support enabeld, you may "
             "need to install the OpenSSL run-time libraries.");

    ui->chatDisplayTextEdit->setText(noSslMsg);
  }

  // 加密建立后发送已加密信号
  connect(&socket, SIGNAL(encrypted()), this, SLOT(connectedToServer()));

  // 提示SSL错误
  connect(&socket, SIGNAL(sslErrors(const QList<QSslError> &)), this, SLOT(sslErrors(const QList<QSslError> &)));

  connect(&socket, SIGNAL(disconnected()), this, SLOT(connectionClosed()));
  // 有数据读取
  connect(&socket, SIGNAL(readyRead()), this, SLOT(receiveMessage()));
  connect(&socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(socketError()));
}

Client::~Client()
{
  if (socket.isOpen())
  {
    socket.close();
  }

  delete ui;
}
/*连接和断开连接按键*/
void Client::connectDisconnectButtonPressed()
{
  ui->connectDisconnectButton->setEnabled(false);

  if (socket.state() == QAbstractSocket::UnconnectedState)
  {
    // 初始化SSL连接
    socket.connectToHostEncrypted(ui->hostnameLineEdit->text(), ui->portSpinBox->value());
  }
  else
  {
    socket.close();
  }
}
/*发生按键*/
void Client::sendButtonPressed()
{
  QString message = ui->inputLineEdit->text();
  if (!message.isEmpty())
  {
    message += '\n';
    socket.write(message.toLocal8Bit().constData());
    ui->inputLineEdit->clear();
  }
}

void Client::connectedToServer()
{
  ui->connectDisconnectButton->setText("Disconnect");
  ui->connectDisconnectButton->setEnabled(true);
  ui->inputLineEdit->setEnabled(true);
  ui->sendButton->setEnabled(true);
  ui->chatDisplayTextEdit->clear();
}

/**Process SSL errors
 * 提示错误信息
*/
void Client::sslErrors(const QList<QSslError> &errors)
{
  QString errorStrings;
  foreach (QSslError error, errors)
  {
    errorStrings += error.errorString();
    if (error != errors.last())
    {
      errorStrings += '\n';
    }
  }

  // Display error details to user and ask for permission to proceed anyway
  QMessageBox::StandardButton result = QMessageBox::question(this, "SSL Errors",
    QString("The following errors were encountered while negotiating the SSL connection:\n\n%1\n\nProceed anyway?").arg(errorStrings),
    QMessageBox::Yes|QMessageBox::No);
  if (result == QMessageBox::Yes)
  {
    socket.ignoreSslErrors();
  }
}
/**接收到的消息，直接输入到TextEdit
 * 时间+消息内容
*/
void Client::receiveMessage()
{
  if (socket.canReadLine())
  {
    ui->chatDisplayTextEdit->append(QString("[%1] %2")
                                    .arg(QDateTime::currentDateTime().toString("hh:mm:ss.zzz ap"))
                                    .arg(socket.readLine().constData()));
  }
}
/**连接关闭
*/
void Client::connectionClosed()
{
  ui->connectDisconnectButton->setText("Connect");
  ui->connectDisconnectButton->setEnabled(true);
  ui->inputLineEdit->setEnabled(false);
  ui->sendButton->setEnabled(false);
}
/**socket发生错误
*/
void Client::socketError()
{
  ui->chatDisplayTextEdit->setText(QString("Socket Error: %1").arg(socket.errorString()));
  if (socket.state() != QAbstractSocket::ConnectedState)
  {
    connectionClosed();
  }
  socket.close();
}
