#include <cassert>
#include <QDateTime>
#include <QFileDialog>
#include <QFileInfo>
#include "server.h"
#include "ui_server.h"

const QString INVALID_FILE_MESSAGE = "Existing and readable key and certificate files must be specified.";

Server::Server(QWidget *parent) :  QMainWindow(parent), ui(new Ui::Server)
{
  ui->setupUi(this);

  //检查SSL是否支持，如果不支持会提示怎么使能支持
  if (QSslSocket::supportsSsl())
  {
    //使能秘钥和证书的部件
    ui->sslFilesGroupBox->setEnabled(true);
    //提示加载证书和加密文件
    ui->logTextEdit->setText(INVALID_FILE_MESSAGE);
  }
  else
  {
    QString noSslMsg = QString("%1\n%2")
        .arg("*** Your version of Qt does not support SSL ***")
        .arg("You must obtain a version of Qt that has SSL"
             "support enabled.  If you believe that your "
             "version of Qt has SSL support enabeld, you may "
             "need to install the OpenSSL run-time libraries.");
    ui->logTextEdit->setText(noSslMsg);
  }
  //QTcpServer监听连接
  connect(&sslServer, SIGNAL(newConnection()), this, SLOT(acceptConnection()));
}

Server::~Server()
{
  if (sslServer.isListening())
  {
    sslServer.close();
  }

  foreach (QSslSocket *socket, sockets)
  {
    delete socket;
  }

  delete ui;
}
/*开始和停止按键*/
void Server::startStopButtonClicked()
{
  if (sslServer.isListening())
  {
    sslServer.close();
    ui->startStopButton->setText("Start Server");
    ui->logTextEdit->clear();
  }
  else//开始监听
  {
    int port = ui->portSpinBox->value();
    if (sslServer.listen(QHostAddress::Any, port))
    {
      ui->startStopButton->setText("Stop Server");
      ui->logTextEdit->setText(QString("Server listenting for connections on %1\n").arg(port));
    }
    else
    {
      ui->logTextEdit->setText(QString("Failed to start server: %1\n").arg(sslServer.errorString()));
    }
  }
}

/*添加加密文件*/
void Server::keyButtonClicked()
{
  QString filename = QFileDialog::getOpenFileName(this, "Select Key File");
  if (!filename.isNull())
  {
    ui->keyLineEdit->setText(filename);
  }
}

/*添加证书文件*/
void Server::certificateButtonClicked()
{
  QString filename = QFileDialog::getOpenFileName(this, "Select Certificate File");
  if (!filename.isNull())
  {
    ui->certificateLineEdit->setText(filename);
  }
}

/*改变加密文件*/
void Server::keyFileChanged(const QString &filename)
{
  key = filename;
  checkFileStatus();
}
/*改变证书文件*/
void Server::certificateFileChanged(const QString &filename)
{
  certificate = filename;
  checkFileStatus();
}
/*检查文件的存在性和可读性，都存在就清空TextEdit*/
void Server::checkFileStatus()
{
  QFileInfo keyInfo(key);
  QFileInfo certificateInfo(certificate);
  if (keyInfo.exists() && keyInfo.isReadable() &&
      certificateInfo.exists() && certificateInfo.isReadable())
  {
    ui->startStopButton->setEnabled(true);
    ui->logTextEdit->clear();
  }
  else
  {
    ui->startStopButton->setEnabled(false);
    ui->logTextEdit->setText(INVALID_FILE_MESSAGE);
  }
}

// Accept connection from server and initiate the SSL handshake
//接受连接客户端连接，初始化SSL握手
void Server::acceptConnection()
{
    QSslSocket *socket = dynamic_cast<QSslSocket *>(sslServer.nextPendingConnection());
    assert(socket);

    //机密连接建立时，QSslSocket 发射机密完成信号
    connect(socket, SIGNAL(encrypted()), this, SLOT(handshakeComplete()));

    //发生错误时，上报SSL错误
    connect(socket, SIGNAL(sslErrors(const QList<QSslError> &)), this, SLOT(sslErrors(const QList<QSslError> &)));

    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(connectionFailure()));
    //设置私钥和证书
    socket->setPrivateKey(key);
    socket->setLocalCertificate(certificate);
    //设置验证模式
    socket->setPeerVerifyMode(QSslSocket::VerifyNone);
    //开启加密服务
    socket->startServerEncryption();
}

// SSL握手成功后，接收消息提醒
void Server::handshakeComplete()
{
    QSslSocket *socket = dynamic_cast<QSslSocket *>(sender());//sender()是槽函数里收到的发生信号的Object指针，其他地方为0
    assert(socket);

    connect(socket, SIGNAL(disconnected()), this, SLOT(connectionClosed()));
    connect(socket, SIGNAL(readyRead()), this, SLOT(receiveMessage()));

    ui->logTextEdit->append(QString("[%1] Accepted connection from %2:%3")
                          .arg(QDateTime::currentDateTime().toString("hh:mm:ss.zzz ap"))
                          .arg(socket->peerAddress().toString())
                          .arg(socket->peerPort()));
    //保存socket
    sockets.push_back(socket);
}
/*SSL错误信息*/
void Server::sslErrors(const QList<QSslError> &errors)
{
  QSslSocket *socket = dynamic_cast<QSslSocket *>(sender());
  assert(socket);

  QString errorStrings;
  foreach (QSslError error, errors)
  {
    errorStrings += error.errorString();
    if (error != errors.last())
    {
      errorStrings += ';';
    }
  }

  ui->logTextEdit->append(QString("[%1] %2:%3 reported the following SSL errors: %4")
      .arg(QDateTime::currentDateTime().toString("hh:mm:ss.zzz ap"))
                          .arg(socket->peerAddress().toString())
                          .arg(socket->peerPort())
                          .arg(errorStrings));
}

/*接收到的信息*/
void Server::receiveMessage()
{
  QSslSocket *socket = dynamic_cast<QSslSocket *>(sender());
  assert(socket);

  if (socket->canReadLine())
  {
    QByteArray message = socket->readLine();
    QString sender = QString("%1:%2")
        .arg(socket->peerAddress().toString())
        .arg(socket->peerPort());

    ui->logTextEdit->append(QString("[%1] %2 sent: %3")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss.zzz ap"))//时间
        .arg(sender)//地址+端口
        .arg(message.constData()));//消息

    sender += " -> ";
    //返回所有连接消息
    foreach (QSslSocket *s, sockets)
    {
      s->write(sender.toLocal8Bit().constData());
      s->write(message);
    }
  }
}
/*socket连接关闭*/
void Server::connectionClosed()
{
  QSslSocket *socket = dynamic_cast<QSslSocket *>(sender());
  assert(socket);

  ui->logTextEdit->append(QString("[%1] Connection from %2:%3 closed: %4")
                          .arg(QDateTime::currentDateTime().toString("hh:mm:ss.zzz ap"))
                          .arg(socket->peerAddress().toString())
                          .arg(socket->peerPort())
                          .arg(socket->errorString()));
  sockets.removeOne(socket);
  socket->disconnect();
  socket->deleteLater();
}

/*socket连接失败*/
void Server::connectionFailure()
{
  QSslSocket *socket = dynamic_cast<QSslSocket *>(sender());
  assert(socket);

  ui->logTextEdit->append(QString("[%1] Connection from %2:%3 failed: %4")
                          .arg(QDateTime::currentDateTime().toString("hh:mm:ss.zzz ap"))
                          .arg(socket->peerAddress().toString())
                          .arg(socket->peerPort())
                          .arg(socket->errorString()));
  sockets.removeOne(socket);
  socket->disconnect();
  socket->deleteLater();
}
