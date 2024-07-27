package com.qimu.qiauth.model.dto.user;

import lombok.Data;

import java.io.Serializable;

/**
 * @Author: QiMu
 * @Date: 2024/05/27 11:35:19
 * @Version: 1.0
 * @Description: 用户注册请求体
 */
@Data
public class UserRegisterRequest implements Serializable {

    private static final long serialVersionUID = 3191241716373120793L;

    /**
     * 用户帐户
     */
    private String userAccount;

    /**
     * 用户密码
     */
    private String userPassword;

    /**
     * 检查密码
     */
    private String checkPassword;
    /**
     * 用户名
     */
    private String userName;
}
