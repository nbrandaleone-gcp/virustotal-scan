FROM ruby:3.3

WORKDIR /app

COPY . .

RUN gem install --no-document bundler \
    && bundle config set --local frozen true \
    && bundle config set --local without "development test" \
    && bundle install

ENTRYPOINT ["bundle", "exec", "ruby","app.rb"]
