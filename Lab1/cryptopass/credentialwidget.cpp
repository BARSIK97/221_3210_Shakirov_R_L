#include "credentialwidget.h"
#include "ui_credentialwidget.h"
#include <QDebug>

CredentialWidget::CredentialWidget(const QString &site,  int id, QWidget *parent)
    : QWidget(parent), ui(new Ui::CredentialWidget), m_id(id)
{
    setMinimumHeight(50);
    ui->setupUi(this);
    ui->lblSite->setText(site);

    connect(ui->btnLoginCopy, &QPushButton::clicked, this, &CredentialWidget::on_btnLoginCopy_clicked);
    connect(ui->btnPassCopy, &QPushButton::clicked, this, &CredentialWidget::on_btnPassCopy_clicked);
}

QString CredentialWidget::site() const
{
    return ui->lblSite->text();
}
/*
void CredentialWidget::on_btnLoginCopy_clicked()
{
    qDebug() << "*** Login ID:" << m_id;
    emit decryptLogin(m_id);
}
*/
void CredentialWidget::on_btnPassCopy_clicked()
{
    qDebug() << "*** Password ID:" << m_id;
    emit decryptPassword(m_id);
}

CredentialWidget::~CredentialWidget()
{
    delete ui;
}
