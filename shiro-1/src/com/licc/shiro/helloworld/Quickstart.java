package com.licc.shiro.helloworld;

 /*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Simple Quickstart application showing how to use Shiro's API.
 * 简单的快速开始以演示如何使用shiro
 *
 * @since 0.9 RC2
 */
public class Quickstart {

    private static final transient Logger log = LoggerFactory.getLogger(Quickstart.class);


    public static void main(String[] args) {

        // The easiest way to create a Shiro SecurityManager with configured
        // 最简单的方式创建一个SecurityManager
        // realms, users, roles and permissions is to use the simple INI config.
        // realms:访问安全数据 users:用户 roles:权限 permissions:行为 使用shiro.ini配置文件
        // We'll do that by using a factory that can ingest a .ini file and
        // return a SecurityManager instance:

        // Use the shiro.ini file at the root of the classpath
        // (file: and url: prefixes load from files and urls respectively):
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();

        // for this simple example quickstart, make the SecurityManager
        // accessible as a JVM singleton.  Most applications wouldn't do this
        // and instead rely on their container configuration or web.xml for
        // webapps.  That is outside the scope of this simple quickstart, so
        // we'll just do the bare minimum so you can continue to get a feel
        // for things.
        SecurityUtils.setSecurityManager(securityManager);

        // Now that a simple Shiro environment is set up, let's see what you can do:

        // get the currently executing user:
        // 获取当前的Subject.调用SecurityUtils.getSubject()方法
        Subject currentUser = SecurityUtils.getSubject();

        // Do some stuff with a Session (no need for a web or EJB container!!!)
        // 测试使用Session
        // 获取Sesison:调用Subject.getSession()方法
        Session session = currentUser.getSession();
        // 放置一个属性
        session.setAttribute("someKey", "aValue");
        // 取出该属性值
        String value = (String) session.getAttribute("someKey");
        if (value.equals("aValue")) {
            log.info("---> Retrieved the correct value! [" + value + "]");
        }

        // let's login the current user so we can check against roles and permissions:
        // 测试当前的用户是否已经被认证,即是否已经登录
        // 调用Subject.isAuthenticated()方法
        if (!currentUser.isAuthenticated()) {
            // 把用户名和密码封装为UsernamePasswordToken对象
            UsernamePasswordToken token = new UsernamePasswordToken("lonestarr", "vespa");
            // 未知的账户
            //UsernamePasswordToken token = new UsernamePasswordToken("unknown", "unknown");
            // 错误的凭证
            //UsernamePasswordToken token = new UsernamePasswordToken("lonestarr", "errorPassword");

            // remember me
            token.setRememberMe(true);
            try {
                // 调用Subject.login(AuthenticationToken var1)方法执行登录
                currentUser.login(token);
            }
            // 未知的账户异常:若没有指定的账户,shiro将会抛出UnknownAccountException异常
            catch (UnknownAccountException uae) {
                log.info("---> There is no user with username of " + token.getPrincipal());
                return;
            }
            // 错误的凭证异常(密码不正确):若账户存在,但密码不匹配,shiro会抛出IncorrectCredentialsException异常
            catch (IncorrectCredentialsException ice) {
                log.info("---> Password for account " + token.getPrincipal() + " was incorrect!");
                return;
            }
            // 用户被锁定异常:
            catch (LockedAccountException lae) {
                log.info("The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.");
            }
            // ... catch more exceptions here (maybe custom ones specific to your application?
            // 所有认证异常的父类
            catch (AuthenticationException ae) {
                //unexpected condition?  error?
            }
        }

        //say who they are:
        //print their identifying principal (in this case, a username):
        log.info("---> User [" + currentUser.getPrincipal() + "] logged in successfully.");

        //test a role:
        // 测试是否有某一个角色:调用Subject.hasRole(String roleIdentifier)方法
        if (currentUser.hasRole("schwartz")) {
        // 不存在的角色
        //if (currentUser.hasRole("notExist")) {
            log.info("---> May the Schwartz be with you!");
        } else {
            log.info("---> Hello, mere mortal.");
            return;
        }

        //test a typed permission (not instance-level)
        // 测试用户是否具备某一个行为:调用Subject.isPermitted(String permission)方法
        if (currentUser.isPermitted("lightsaber:wield(do anything)")) {
            log.info("---> You may use a lightsaber ring.  Use it wisely.");
        } else {
            log.info("Sorry, lightsaber rings are for schwartz masters only.");
        }

        //a (very powerful) Instance Level permission:
        // 测试用户是否具备某一个行为(更具体)
        //if (currentUser.isPermitted("winnebago:drive:eagle5")) {
        if (currentUser.isPermitted("user:delete:licc")) {
            log.info("---> You are permitted to 'drive' the winnebago with license plate (id) 'eagle5'.  " +
                    "Here are the keys - have fun!");
        } else {
            log.info("Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
        }

        // true:被认证了
        System.out.println("---> " + currentUser.isAuthenticated());

        //all done - log out!
        // 执行登出:调用Subject.Logout()方法
        currentUser.logout();

        // false:登出后未被认证
        System.out.println("---> " + currentUser.isAuthenticated());

        System.exit(0);
    }
}
