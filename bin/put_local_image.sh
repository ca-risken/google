#!/bin/bash -e

cd "$(dirname "$0")"

# load env
. ../env.sh

# setting remote repository
TAG="local-test-$(date '+%Y%m%d')"
IMAGE_GOOGLE="google/google"
IMAGE_ASSET="google/asset"
IMAGE_CLOUDSPLOIT="google/cloudsploit"
IMAGE_SCC="google/scc"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
REGISTORY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

# build & push
aws ecr get-login-password --region ${AWS_REGION} \
  | docker login \
    --username AWS \
    --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

docker build --build-arg GITHUB_USER=${GITHUB_USER} --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} -t ${IMAGE_GOOGLE}:${TAG} ../src/google/
docker build --build-arg GITHUB_USER=${GITHUB_USER} --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} -t ${IMAGE_ASSET}:${TAG} ../src/asset/
docker build --build-arg GITHUB_USER=${GITHUB_USER} --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} -t ${IMAGE_CLOUDSPLOIT}:${TAG} ../src/cloudsploit/
docker build --build-arg GITHUB_USER=${GITHUB_USER} --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} -t ${IMAGE_SCC}:${TAG} ../src/scc/

docker tag ${IMAGE_GOOGLE}:${TAG}      ${REGISTORY}/${IMAGE_GOOGLE}:${TAG}
docker tag ${IMAGE_ASSET}:${TAG}       ${REGISTORY}/${IMAGE_ASSET}:${TAG}
docker tag ${IMAGE_CLOUDSPLOIT}:${TAG} ${REGISTORY}/${IMAGE_CLOUDSPLOIT}:${TAG}
docker tag ${IMAGE_SCC}:${TAG}         ${REGISTORY}/${IMAGE_SCC}:${TAG}

docker push ${REGISTORY}/${IMAGE_GOOGLE}:${TAG}
docker push ${REGISTORY}/${IMAGE_ASSET}:${TAG}
docker push ${REGISTORY}/${IMAGE_CLOUDSPLOIT}:${TAG}
docker push ${REGISTORY}/${IMAGE_SCC}:${TAG}
