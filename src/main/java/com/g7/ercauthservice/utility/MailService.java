package com.g7.ercauthservice.utility;

import com.g7.ercauthservice.config.MailConfiguration;
import com.g7.ercauthservice.config.ThymeleafConfiguration;
import com.g7.ercauthservice.enums.MailType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.io.IOException;

@Service
@Slf4j
public class MailService {

    @Autowired
    private MailConfiguration mail;
    @Autowired
    private ThymeleafConfiguration thymeleaf;

    @Async
    public void sendEmail(String address, String subject, MailType type,String token) throws MessagingException, IOException {

        String senderName = "ERC University of Ruhuna";
        System.out.println("Init");
        MimeMessage mimeMessage = mail.getJavaMailSender().createMimeMessage();
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage);
        mimeMessageHelper.setFrom("harshanadun52@gmail.com", senderName);
        mimeMessageHelper.setTo(address);
        mimeMessageHelper.setSubject(subject);
        mimeMessageHelper.setText(htmlToString(type,token), true);
        System.out.println("Start sending");
        mail.getJavaMailSender().send(mimeMessage);
        System.out.println("Email has been sent " + address);
    }

    public String htmlToString(MailType type,String token) {
        Context ctx = new Context();
        String note;
        switch (type) {
            case MAIL_VERIFY:
                note = "Thank you for choosing ethical review committee." +
                        " First, you need to set up your account." +
                        " Just press the button below.";
                ctx.setVariable("message", note);
                ctx.setVariable("button", "Complete Signup Process");
                ctx.setVariable("url", "https://erc-ruh.live/signup?token="+token);
                return thymeleaf.templateEngine().process("email.html", ctx);

            case INVITE_CLERK:
                note = "You are appointed as a CLERK of Ethical review committee" +
                        "of Medical Faculty University of Ruhuna. Please complete the sign up process.";
                ctx.setVariable("message", note);
                ctx.setVariable("button", "Complete Signup Process");
                ctx.setVariable("url", "https://erc-ruh.live/signup?token="+token);
                return thymeleaf.templateEngine().process("email.html", ctx);

            case INVITE_REVIEWER:
                note = "You are appointed as a REVIEWER of Ethical review committee" +
                        "of Medical Faculty University of Ruhuna. Please complete the sign up process. ";
                ctx.setVariable("message", note);
                ctx.setVariable("button", "Complete Signup Process");
                ctx.setVariable("url", "https://erc-ruh.live/signup?token="+token);
                return thymeleaf.templateEngine().process("email.html", ctx);

            case INVITE_SECRETARY:
                note = "You are appointed as a SECRETARY of Ethical review committee" +
                        "of Medical Faculty University of Ruhuna, Please complete the sign up process.";
                ctx.setVariable("message", note);
                ctx.setVariable("button", "Complete Signup Process");
                ctx.setVariable("url", "https://erc-ruh.live/signup?token="+token);
                return thymeleaf.templateEngine().process("email.html", ctx);

            case FORGOT_PASSWORD:
                note = "Click to bellow button to reset your password";
                ctx.setVariable("message", note);
                ctx.setVariable("button", "Reset Password");
                ctx.setVariable("url", "https://erc-ruh.live/forgot-password?token="+token);
                return thymeleaf.templateEngine().process("email.html", ctx);

            case ROLE_CHANGE:
                note = "Your privileges have been modified. Please login to the system to view them.";
                ctx.setVariable("message", note);
                ctx.setVariable("button", "Click to Login");
                ctx.setVariable("url", "https://picoworkers.com/login.php");
                return thymeleaf.templateEngine().process("email.html", ctx);
        }
        return null;
    }
}
