package com.qimu.qiauth.model.dto.user;

import lombok.Data;

import java.io.Serializable;

/**
 * @Author: QiMu
 * @Date: 2023/09/04 11:34:09
 * @Version: 1.0
 * @Description: 用户注册请求体
 */
@Data
public class UserEmailRegisterRequest implements Serializable {

    private static final long serialVersionUID = 3191241716373120793L;

    /**
     * 电子邮件帐户
     */
    private String emailAccount;

    /**
     * 验证码
     */
    private String captcha;

    /**
     * 用户名
     */
    private String userName;

    /**
     * 邀请代码
     */
    private String invitationCode;
}
