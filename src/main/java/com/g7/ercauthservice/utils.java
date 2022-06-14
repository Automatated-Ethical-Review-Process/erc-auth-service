package com.g7.ercauthservice;

import com.g7.ercauthservice.config.MailConfiguration;
import com.g7.ercauthservice.config.ThymeleafConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.util.Arrays;
import java.util.Date;

@Service
@Slf4j
public class utils {

    @Autowired
    private MailConfiguration mail ;
    @Autowired
    private ThymeleafConfiguration thymeleaf;

    //@Async
    public void sendVerificationEmail(String email) throws MessagingException, IOException {

        String fromAddress = "harshanadun52@gmail.com";
        String senderName = "ERC University of Ruhuna";
        String subject = "Please verify your subscription account";
        String content = htmlToString("Sandaruwan Lakshitha");
        System.out.println("Init");
        MimeMessage mimeMessage = mail.getJavaMailSender().createMimeMessage();
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage);

        mimeMessageHelper.setFrom(fromAddress,senderName);
        mimeMessageHelper.setTo(email);
        mimeMessageHelper.setSubject(subject);

        mimeMessageHelper.setText(content,true);
        System.out.println("Start sending");

        mail.getJavaMailSender().send(mimeMessage);
        System.out.println("Email has been sent");
    }

    public String htmlToString(String recipientName) throws IOException {

        Context ctx = new Context();
        ctx.setVariable("name", recipientName);
        ctx.setVariable("subscriptionDate", new Date());
        ctx.setVariable("hobbies", Arrays.asList("Cinema", "Sports", "Music"));
        return thymeleaf.templateEngine().process("email.html",ctx);

    }
}
