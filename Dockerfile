FROM bitnami/kubectl:1.22 as kube

FROM toniblyx/prowler:2.11.0

COPY --from=kube /opt/bitnami/kubectl/bin/kubectl ./

COPY ./entrypoint.sh ./

ENTRYPOINT ["./entrypoint.sh"]
