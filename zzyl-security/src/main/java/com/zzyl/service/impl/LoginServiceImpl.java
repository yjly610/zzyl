package com.zzyl.service.impl;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.json.JSONUtil;
import com.zzyl.constant.UserCacheConstant;
import com.zzyl.dto.LoginDto;
import com.zzyl.exception.BaseException;
import com.zzyl.properties.JwtTokenManagerProperties;
import com.zzyl.service.*;
import com.zzyl.utils.JwtUtil;
import com.zzyl.utils.ObjectUtil;
import com.zzyl.vo.ResourceVo;
import com.zzyl.vo.RoleVo;
import com.zzyl.vo.UserAuth;
import com.zzyl.vo.UserVo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.zzyl.service.LoginService;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
public class LoginServiceImpl implements LoginService {
    //注入认证管理器
    @Autowired
    private AuthenticationManager authenticationManager;

    //注入角色Service
    @Autowired
    private RoleService roleService;

    //注入资源Service
    @Autowired
    private ResourceService resourceService;

    //JWT配置类
    @Autowired
    private JwtTokenManagerProperties jwtTokenManagerProperties;

    //导入Redis
    @Autowired
    private StringRedisTemplate redisTemplate;

    /**
     * 登录
     * @param loginDto
     */
    @Override
    public UserVo login(LoginDto loginDto) {
        //准备安全框架所需资源
        UsernamePasswordAuthenticationToken upat =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(),loginDto.getPassword());

        //调用安全框架security验证（认证管理器）
        Authentication authenticate = authenticationManager.authenticate(upat);

        if (ObjectUtil.isEmpty(authenticate)) {
            throw new BaseException("账户不存在！");
        }

        //对象类型转换
        UserAuth userAuth = (UserAuth) authenticate.getPrincipal();
        UserVo userVo = BeanUtil.toBean(userAuth, UserVo.class);

        //获取用户资源列表
        List<ResourceVo> resourceVoList = resourceService.findResourceVoListByUserId(userVo.getId());
        Set<String> rosourceSet =
                resourceVoList.stream()
                        .filter(resourceVo -> "r".equals(resourceVo.getResourceType()))
                        .map(ResourceVo::getRequestPath)
                        .collect(Collectors.toSet());
        userVo.setResourceRequestPaths(rosourceSet);

        //获取用户角色列表
        List<RoleVo> roleVoList = roleService.findRoleVoListByUserId(userVo.getId());
        Set<String> roleSet =
                roleVoList.stream().map(RoleVo::getLabel).collect(Collectors.toSet());
        userVo.setRoleLabels(roleSet);
        //颁发JwtToken
        Map<String,Object> map = new HashMap<>();
        map.put("currentUser", JSONUtil.toJsonStr(userVo));
        String jwtToken =
                JwtUtil.createJWT(jwtTokenManagerProperties.getBase64EncodedSecretKey()
                , jwtTokenManagerProperties.getTtl(), map);

        //生成UUID
        String uuidToken = UUID.randomUUID().toString();

        //过期时间同步
        Long outTime = Long.valueOf(jwtTokenManagerProperties.getTtl() / 1000);

        //存储Redis
            //数据key准备
            String uuidTokenKey = UserCacheConstant.USER_TOKEN + userVo.getUsername();
            String jwtTokenKey = UserCacheConstant.JWT_TOKEN + uuidToken;
        redisTemplate.opsForValue().set(uuidTokenKey,uuidToken,outTime, TimeUnit.SECONDS);
        redisTemplate.opsForValue().set(jwtTokenKey,jwtToken,outTime, TimeUnit.SECONDS);

        //uuidToken返回前端
        userVo.setUserToken(uuidToken);

        return userVo;
    }
}
